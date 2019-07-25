from __future__ import annotations

import json
import logging
import random
import time
import uuid
from base64 import b64encode
from datetime import datetime, timedelta
from os import urandom

import rest_framework.authtoken.models
from django.conf import settings
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser
from django.core.exceptions import ValidationError
from django.core.mail import EmailMessage
from django.core.signing import Signer
from django.core.validators import RegexValidator
from django.db import models
from django.db.models import Manager
from django.template.loader import get_template
from django.utils import timezone
from django.utils.crypto import constant_time_compare
from rest_framework.exceptions import APIException

from desecapi import pdns

logger = logging.getLogger(__name__)


def validate_lower(value):
    if value != value.lower():
        raise ValidationError('Invalid value (not lowercase): %(value)s',
                              code='invalid',
                              params={'value': value})


def validate_upper(value):
    if value != value.upper():
        raise ValidationError('Invalid value (not uppercase): %(value)s',
                              code='invalid',
                              params={'value': value})


class MyUserManager(BaseUserManager):
    def create_user(self, email, password, **extra_fields):
        """
        Creates and saves a User with the given email, date of
        birth and password.
        """
        if not email:
            raise ValueError('Users must have an email address')

        email = self.normalize_email(email)
        extra_fields.setdefault('registration_remote_ip')
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password):
        """
        Creates and saves a superuser with the given email, date of
        birth and password.
        """
        user = self.create_user(email, password=password)
        user.is_admin = True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser):
    email = models.EmailField(
        verbose_name='email address',
        max_length=191,
        unique=True,
    )
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    registration_remote_ip = models.CharField(max_length=1024, blank=True)
    created = models.DateTimeField(auto_now_add=True)
    limit_domains = models.IntegerField(default=settings.LIMIT_USER_DOMAIN_COUNT_DEFAULT, null=True, blank=True)

    objects = MyUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def get_full_name(self):
        return self.email

    def get_short_name(self):
        return self.email

    def get_or_create_first_token(self):
        try:
            token = Token.objects.filter(user=self).earliest('created')
        except Token.DoesNotExist:
            token = Token.objects.create(user=self)
        return token.key

    def __str__(self):
        return self.email

    # noinspection PyMethodMayBeStatic
    def has_perm(self, *_):
        """Does the user have a specific permission?"""
        # Simplest possible answer: Yes, always
        return True

    # noinspection PyMethodMayBeStatic
    def has_module_perms(self, *_):
        """Does the user have permissions to view the app `app_label`?"""
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        """Is the user a member of staff?"""
        # Simplest possible answer: All admins are staff
        return self.is_admin

    def activate(self):
        self.is_active = True
        self.save()

    def change_email(self, email):
        old_email = self.email
        self.email = email
        self.validate_unique()
        self.save()

        self.send_email('change-email-confirmation-old-email', recipient=old_email)

    def change_password(self, raw_password):
        self.set_password(raw_password)
        self.save()
        self.send_email('password-change-confirmation')

    def send_email(self, reason, context=None, recipient=None):
        context = context or {}
        reasons = [
            'activate',
            'activate-with-domain',
            'change-email',
            'change-email-confirmation-old-email',
            'password-change-confirmation',
            'reset-password',
            'delete-user',
        ]
        recipient = recipient or self.email
        if reason not in reasons:
            raise ValueError('Cannot send email to user {} without a good reason: {}'.format(self.email, reason))
        content_tmpl = get_template('emails/{}/content.txt'.format(reason))
        subject_tmpl = get_template('emails/{}/subject.txt'.format(reason))
        from_tmpl = get_template('emails/from.txt')
        footer_tmpl = get_template('emails/footer.txt')
        email = EmailMessage(subject_tmpl.render(context).strip(),
                             content_tmpl.render(context) + footer_tmpl.render(),
                             from_tmpl.render(context),
                             [recipient])
        logger.warning('Sending email for user account %s (reason: %s)', str(self.pk), reason)
        email.send()


class Token(rest_framework.authtoken.models.Token):
    key = models.CharField("Key", max_length=40, db_index=True, unique=True)
    # relation to user is a ForeignKey, so each user can have more than one token
    user = models.ForeignKey(
        User, related_name='auth_tokens',
        on_delete=models.CASCADE, verbose_name="User"
    )
    name = models.CharField("Name", max_length=64, default="")
    user_specific_id = models.BigIntegerField("User-Specific ID")

    def save(self, *args, **kwargs):
        if not self.user_specific_id:
            self.user_specific_id = random.randrange(16 ** 8)
        super().save(*args, **kwargs)  # Call the "real" save() method.

    def generate_key(self):
        return b64encode(urandom(21)).decode('utf-8').replace('/', '-').replace('=', '_').replace('+', '.')

    class Meta:
        abstract = False
        unique_together = (('user', 'user_specific_id'),)


class Domain(models.Model):
    created = models.DateTimeField(auto_now_add=True)
    name = models.CharField(max_length=191,
                            unique=True,
                            validators=[validate_lower,
                                        RegexValidator(regex=r'^[a-z0-9_.-]*[a-z]$',
                                                       message='Invalid value (not a DNS name).',
                                                       code='invalid_domain_name')
                                        ])
    owner = models.ForeignKey(User, on_delete=models.PROTECT, related_name='domains')
    published = models.DateTimeField(null=True, blank=True)
    minimum_ttl = models.PositiveIntegerField(default=settings.MINIMUM_TTL_DEFAULT)

    @property
    def keys(self):
        return pdns.get_keys(self)

    def has_local_public_suffix(self):
        return self.partition_name()[1] in settings.LOCAL_PUBLIC_SUFFIXES

    def parent_domain_name(self):
        return self.partition_name()[1]

    def partition_name(domain):
        name = domain.name if isinstance(domain, Domain) else domain  # TODO where is this used?
        subname, _, parent_name = name.partition('.')
        return subname, parent_name or None

    def save(self, *args, **kwargs):
        self.full_clean(validate_unique=False)
        super().save(*args, **kwargs)

    def update_delegation(self, child_domain: Domain):
        child_subname, child_domain_name = child_domain.partition_name()
        if self.name != child_domain_name:
            raise ValueError('Cannot update delegation of %s as it is not an immediate child domain of %s.' %
                             (child_domain.name, self.name))

        if child_domain.pk:
            # Domain real: set delegation
            child_keys = child_domain.keys
            if not child_keys:
                raise APIException('Cannot delegate %s, as it currently has no keys.' % child_domain.name)

            RRset.objects.create(domain=self, subname=child_subname, type='NS', ttl=3600, contents=settings.DEFAULT_NS)
            RRset.objects.create(domain=self, subname=child_subname, type='DS', ttl=300,
                                 contents=[ds for k in child_keys for ds in k['ds']])
        else:
            # Domain not real: remove delegation
            for rrset in self.rrset_set.filter(subname=child_subname, type__in=['NS', 'DS']):
                rrset.delete()

    def __str__(self):
        return self.name

    class Meta:
        ordering = ('created',)


def get_default_value_created():
    return timezone.now()


def get_default_value_due():
    return timezone.now() + timedelta(days=7)


def get_default_value_mref():
    return "ONDON" + str(time.time())


class Donation(models.Model):
    created = models.DateTimeField(default=get_default_value_created)
    name = models.CharField(max_length=255)
    iban = models.CharField(max_length=34)
    bic = models.CharField(max_length=11)
    amount = models.DecimalField(max_digits=8, decimal_places=2)
    message = models.CharField(max_length=255, blank=True)
    due = models.DateTimeField(default=get_default_value_due)
    mref = models.CharField(max_length=32, default=get_default_value_mref)
    email = models.EmailField(max_length=255, blank=True)

    def save(self, *args, **kwargs):
        self.iban = self.iban[:6] + "xxx"  # do NOT save account details
        super().save(*args, **kwargs)

    class Meta:
        ordering = ('created',)


class RRsetManager(Manager):
    def create(self, contents=None, **kwargs):
        rrset = super().create(**kwargs)
        for content in contents or []:
            RR.objects.create(rrset=rrset, content=content)
        return rrset


class RRset(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(null=True)
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE)
    subname = models.CharField(
        max_length=178,
        blank=True,
        validators=[
            validate_lower,
            RegexValidator(
                regex=r'^([*]|(([*][.])?[a-z0-9_.-]*))$',
                message='Subname can only use (lowercase) a-z, 0-9, ., -, and _, '
                        'may start with a \'*.\', or just be \'*\'.',
                code='invalid_subname'
            )
        ]
    )
    type = models.CharField(
        max_length=10,
        validators=[
            validate_upper,
            RegexValidator(
                regex=r'^[A-Z][A-Z0-9]*$',
                message='Type must be uppercase alphanumeric and start with a letter.',
                code='invalid_type'
            )
        ]
    )
    ttl = models.PositiveIntegerField()

    objects = RRsetManager()

    DEAD_TYPES = ('ALIAS', 'DNAME')
    RESTRICTED_TYPES = ('SOA', 'RRSIG', 'DNSKEY', 'NSEC3PARAM', 'OPT')

    class Meta:
        unique_together = (("domain", "subname", "type"),)

    @staticmethod
    def construct_name(subname, domain_name):
        return '.'.join(filter(None, [subname, domain_name])) + '.'

    @property
    def name(self):
        return self.construct_name(self.subname, self.domain.name)

    def save(self, *args, **kwargs):
        self.updated = timezone.now()
        self.full_clean(validate_unique=False)
        super().save(*args, **kwargs)

    def __str__(self):
        return '<RRSet domain=%s type=%s subname=%s>' % (self.domain.name, self.type, self.subname)


class RRManager(Manager):
    def bulk_create(self, rrs, **kwargs):
        ret = super().bulk_create(rrs, **kwargs)

        # For each rrset, save once to update published timestamp and trigger signal for post-save processing
        rrsets = {rr.rrset for rr in rrs}
        for rrset in rrsets:
            rrset.save()

        return ret


class RR(models.Model):
    created = models.DateTimeField(auto_now_add=True)
    rrset = models.ForeignKey(RRset, on_delete=models.CASCADE, related_name='records')
    # max_length is determined based on the calculation in
    # https://lists.isc.org/pipermail/bind-users/2008-April/070148.html
    content = models.CharField(max_length=4092)

    objects = RRManager()

    def __str__(self):
        return '<RR %s>' % self.content


class AuthenticatedAction(models.Model):
    """
    Represents an procedure call on a defined set of arguments.

    Subclasses can define additional arguments by adding Django model fields and must define the action to be taken by
    implementing the `act` method.

    AuthenticatedAction provides the `mac` property that returns a Message Authentication Code (MAC) based on the
    state. By default, the state contains the action's name (defined by the `action` property) and a timestamp; the
    state can be extended by (carefully) overriding the `signature_data` method. Any AuthenticatedAction instance of
    the same subclass and state will deterministically have the same MAC, effectively allowing authenticated
    procedure calls by third parties according to the following protocol:

    (1) Instanciate the AuthenticatedAction subclass representing the action to be taken with the desired state,
    (2) provide information on how to instanciate the instance and the MAC to a third party,
    (3) when provided with data that allows instanciation and a valid MAC, take the defined action, possibly with
        additional parameters chosen by the third party that do not belong to the verified state.
    """
    timestamp = models.PositiveIntegerField(default=lambda: int(datetime.timestamp(datetime.now())))

    class Meta:
        managed = False

    def __init__(self, *args, **kwargs):
        # silently ignore any value supplied for the mac value, that makes it easier to use with DRF serializers
        kwargs.pop('mac', None)
        super().__init__(*args, **kwargs)

    @property
    def action(self):
        """
        Returns a human-readable string containing the name of this action class that uniquely identifies this action.
        """
        return ACTION_NAMES[self.__class__]

    @property
    def mac(self):
        """
        Deterministically generates a message authentication code (MAC) for this action, based on the state as defined
        by `self.signature_data`. Identical state is guaranteed to yield identical MAC.
        :return:
        """
        return Signer().signature(json.dumps(self.signature_data()))

    def check_mac(self, mac):
        """
        Checks if the message authentication code (MAC) provided by the first argument matches the state of this action.
        Note that the timestamp is not verified by this method.
        :param mac: Message Authentication Code
        :return: True, if MAC is valid; False otherwise.
        """
        return constant_time_compare(
            mac,
            self.mac,
        )

    def check_expiration(self, validity_period: timedelta, check_time: datetime = datetime.now()):
        """
        Checks if the action's timestamp is no older than the given validity period. Note that the message
        authentication code itself is not verified by this method.
        :param validity_period: How long after issuance the MAC of this action is considered valid.
        :param check_time: Point in time for which to check the expiration. Defaults to datetime.now().
        :return: True, if not considered expired; False otherwise -- i.e. True if valid, False if expired.
        """
        issue_time = datetime.fromtimestamp(self.timestamp)
        check_time = check_time or datetime.now()
        return check_time - issue_time <= validity_period

    # TODO rethink naming convention: Message Authentication Code, but signature_data? Consequently, below method
    #  should be called 'message' or 'message_data'. According the the doc, it should be called 'state'.
    def signature_data(self):
        """
        Returns an ordered list that defines the state of this user action. The signature of this action will be valid
        unless the state changes, therefore if any data included in the return value of this function changes, the
        signature will change. (Technically speaking, the 'state' is the message that `mac` will return the Message
        Authentication Code for.)

        If data is not included in the return value of this function, the signature will be independent of this data.

        Return value must be deterministic and JSON-serializable.

        Use caution when overriding this method, you will usually want to append value to the list returned by the
        parent. Overriding the behavior altogether could result in reducing the state to fewer variables, resulting
        in valid signatures when they were intended to be invalid. The suggested method for overriding is

            def signature_data(self):
                return super().signature_data() + [self.important_value, self.another_added_value]

        :return: List of values to be signed.
        """
        return [self.timestamp, self.action]

    def act(self):
        """
        Conduct the action represented by this class. The result of the action will usually depend on the state of this
        object.
        :return: None
        """
        raise NotImplementedError


class AuthenticatedUserAction(AuthenticatedAction):
    """
    Abstract AuthenticatedAction involving an user instance, incorporating the user's id, email, password, and
    is_active flag into the Message Authentication Code state.
    """
    user = models.ForeignKey(User, on_delete=models.DO_NOTHING)

    class Meta:
        managed = False

    def signature_data(self):
        return super().signature_data() + [self.user.id, self.user.email, self.user.password, self.user.is_active]

    def act(self):
        raise NotImplementedError


class AuthenticatedActivateUserAction(AuthenticatedUserAction):
    domain = models.CharField(max_length=191)

    class Meta:
        managed = False

    def act(self):
        self.user.activate()


class AuthenticatedChangeEmailUserAction(AuthenticatedUserAction):
    new_email = models.EmailField()

    class Meta:
        managed = False

    def signature_data(self):
        return super().signature_data() + [self.new_email]

    def act(self):
        self.user.change_email(self.new_email)


class AuthenticatedResetPasswordUserAction(AuthenticatedUserAction):
    new_password = models.CharField(max_length=128)

    class Meta:
        managed = False

    def act(self):
        self.user.change_password(self.new_password)


class AuthenticatedDeleteUserAction(AuthenticatedUserAction):

    class Meta:
        managed = False

    def act(self):
        self.user.delete()


ACTION_CLASSES = {
    'user/activate': AuthenticatedActivateUserAction,
    'user/change_email': AuthenticatedChangeEmailUserAction,
    'user/reset_password': AuthenticatedResetPasswordUserAction,
    'user/delete': AuthenticatedDeleteUserAction,
}
ACTION_NAMES = {c: n for n, c in ACTION_CLASSES.items()}
