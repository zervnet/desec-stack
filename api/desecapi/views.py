import base64
import binascii

import django.core.exceptions
from django.contrib.auth import user_logged_in
from django.core.mail import EmailMessage
from django.http import Http404
from django.template.loader import get_template
from rest_framework import generics
from rest_framework import mixins
from rest_framework import status
from rest_framework.authentication import get_authorization_header
from rest_framework.exceptions import (NotFound, PermissionDenied, ValidationError)
from rest_framework.generics import (
    GenericAPIView, ListCreateAPIView, RetrieveUpdateDestroyAPIView, UpdateAPIView, get_object_or_404
)
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.reverse import reverse
from rest_framework.views import APIView
from rest_framework.viewsets import GenericViewSet

import desecapi.authentication as auth
from api import settings
from desecapi import serializers
from desecapi.models import Domain, User, RRset, Token, ActivateUserAction, ChangeEmailAction, DeleteUserAction, \
    ResetPasswordAction
from desecapi.pdns_change_tracker import PDNSChangeTracker
from desecapi.permissions import IsOwner, IsDomainOwner
from desecapi.renderers import PlainTextRenderer


class IdempotentDestroy:

    def destroy(self, request, *args, **kwargs):
        try:
            # noinspection PyUnresolvedReferences
            super().destroy(request, *args, **kwargs)
        except Http404:
            pass
        return Response(status=status.HTTP_204_NO_CONTENT)


class DomainView:

    def initial(self, request, *args, **kwargs):
        # noinspection PyUnresolvedReferences
        super().initial(request, *args, **kwargs)
        try:
            # noinspection PyAttributeOutsideInit, PyUnresolvedReferences
            self.domain = self.request.user.domains.get(name=self.kwargs['name'])
        except Domain.DoesNotExist:
            raise Http404


class TokenViewSet(IdempotentDestroy,
                   mixins.CreateModelMixin,
                   mixins.DestroyModelMixin,
                   mixins.ListModelMixin,
                   GenericViewSet):
    serializer_class = serializers.TokenSerializer
    permission_classes = (IsAuthenticated, )
    lookup_field = 'user_specific_id'

    def get_queryset(self):
        return self.request.user.auth_tokens.all()

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class DomainList(ListCreateAPIView):
    serializer_class = serializers.DomainSerializer
    permission_classes = (IsAuthenticated, IsOwner,)

    def get_queryset(self):
        return Domain.objects.filter(owner=self.request.user.pk)

    def perform_create(self, serializer):
        with PDNSChangeTracker():
            domain = serializer.save(owner=self.request.user)
        PDNSChangeTracker.track(lambda: self.auto_delegate(domain))

        # Send dyn email
        if domain.name.endswith('.dedyn.io'):
            content_tmpl = get_template('emails/domain-dyndns/content.txt')
            subject_tmpl = get_template('emails/domain-dyndns/subject.txt')
            from_tmpl = get_template('emails/from.txt')
            context = {
                'domain': domain.name,
                'url': 'https://update.dedyn.io/',
                'username': domain.name,
                'password': self.request.auth.key
            }
            email = EmailMessage(subject_tmpl.render(context),
                                 content_tmpl.render(context),
                                 from_tmpl.render(context),
                                 [self.request.user.email])
            email.send()

    @staticmethod
    def auto_delegate(domain: Domain):
        parent_domain_name = domain.partition_name()[1]
        if parent_domain_name in settings.LOCAL_PUBLIC_SUFFIXES:
            parent_domain = Domain.objects.get(name=parent_domain_name)
            parent_domain.update_delegation(domain)


class DomainDetail(IdempotentDestroy, RetrieveUpdateDestroyAPIView):
    serializer_class = serializers.DomainSerializer
    permission_classes = (IsAuthenticated, IsOwner,)
    lookup_field = 'name'

    def perform_destroy(self, instance: Domain):
        with PDNSChangeTracker():
            instance.delete()
        if instance.has_local_public_suffix():
            parent_domain = Domain.objects.get(name=instance.parent_domain_name())
            with PDNSChangeTracker():
                parent_domain.update_delegation(instance)

    def get_queryset(self):
        return Domain.objects.filter(owner=self.request.user.pk)

    def update(self, request, *args, **kwargs):
        try:
            return super().update(request, *args, **kwargs)
        except django.core.exceptions.ValidationError as e:
            raise ValidationError(detail={"detail": e.message})


class RRsetDetail(IdempotentDestroy, DomainView, RetrieveUpdateDestroyAPIView):
    serializer_class = serializers.RRsetSerializer
    permission_classes = (IsAuthenticated, IsDomainOwner,)

    def get_queryset(self):
        return self.domain.rrset_set

    def get_object(self):
        queryset = self.filter_queryset(self.get_queryset())

        filter_kwargs = {k: self.kwargs[k] for k in ['subname', 'type']}
        obj = get_object_or_404(queryset, **filter_kwargs)

        # May raise a permission denied
        self.check_object_permissions(self.request, obj)

        return obj

    def get_serializer(self, *args, **kwargs):
        kwargs['domain'] = self.domain
        return super().get_serializer(*args, **kwargs)

    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)

        if response.data is None:
            response.status_code = 204
        return response

    def perform_update(self, serializer):
        with PDNSChangeTracker():
            super().perform_update(serializer)

    def perform_destroy(self, instance):
        with PDNSChangeTracker():
            super().perform_destroy(instance)


class RRsetList(DomainView, ListCreateAPIView, UpdateAPIView):
    serializer_class = serializers.RRsetSerializer
    permission_classes = (IsAuthenticated, IsDomainOwner,)

    def get_queryset(self):
        rrsets = RRset.objects.filter(domain=self.domain)

        for filter_field in ('subname', 'type'):
            value = self.request.query_params.get(filter_field)

            if value is not None:
                # TODO consider moving this
                if filter_field == 'type' and value in RRset.RESTRICTED_TYPES:
                    raise PermissionDenied("You cannot tinker with the %s RRset." % value)

                rrsets = rrsets.filter(**{'%s__exact' % filter_field: value})

        return rrsets

    def get_object(self):
        # For this view, the object we're operating on is the queryset that one can also GET. Serializing a queryset
        # is fine as per https://www.django-rest-framework.org/api-guide/serializers/#serializing-multiple-objects.
        # We skip checking object permissions here to avoid evaluating the queryset. The user can access all his RRsets
        # anyways.
        return self.filter_queryset(self.get_queryset())

    def get_serializer(self, *args, **kwargs):
        data = kwargs.get('data')
        if data and 'many' not in kwargs:
            if self.request.method == 'POST':
                kwargs['many'] = isinstance(data, list)
            elif self.request.method in ['PATCH', 'PUT']:
                kwargs['many'] = True
        return super().get_serializer(domain=self.domain, *args, **kwargs)

    def perform_create(self, serializer):
        with PDNSChangeTracker():
            serializer.save(domain=self.domain)

    def perform_update(self, serializer):
        with PDNSChangeTracker():
            serializer.save(domain=self.domain)


class Root(APIView):
    def get(self, request, *_):
        # TODO update
        if self.request.user.is_authenticated:
            routes = {
                'account': reverse('account', request=request),
                'tokens': reverse('token-list', request=request),
                'domains': reverse('domain-list', request=request),
            }
        else:
            routes = {
                'register': reverse('register', request=request),
                'login': reverse('login', request=request),
            }
        return Response(routes)


class DynDNS12Update(APIView):
    authentication_classes = (auth.TokenAuthentication, auth.BasicTokenAuthentication, auth.URLParamAuthentication,)
    renderer_classes = [PlainTextRenderer]

    def _find_domain(self, request):
        def find_domain_name(r):
            # 1. hostname parameter
            if 'hostname' in r.query_params and r.query_params['hostname'] != 'YES':
                return r.query_params['hostname']

            # 2. host_id parameter
            if 'host_id' in r.query_params:
                return r.query_params['host_id']

            # 3. http basic auth username
            try:
                domain_name = base64.b64decode(
                    get_authorization_header(r).decode().split(' ')[1].encode()).decode().split(':')[0]
                if domain_name and '@' not in domain_name:
                    return domain_name
            except IndexError:
                pass
            except UnicodeDecodeError:
                pass
            except binascii.Error:
                pass

            # 4. username parameter
            if 'username' in r.query_params:
                return r.query_params['username']

            # 5. only domain associated with this user account
            if len(r.user.domains.all()) == 1:
                return r.user.domains.all()[0].name
            if len(r.user.domains.all()) > 1:
                ex = ValidationError(detail={
                    "detail": "Request does not specify domain unambiguously.",
                    "code": "domain-ambiguous"
                })
                ex.status_code = status.HTTP_409_CONFLICT
                raise ex

            return None

        name = find_domain_name(request).lower()

        try:
            return self.request.user.domains.get(name=name)
        except Domain.DoesNotExist:
            return None

    @staticmethod
    def find_ip(request, params, version=4):
        if version == 4:
            look_for = '.'
        elif version == 6:
            look_for = ':'
        else:
            raise Exception

        # Check URL parameters
        for p in params:
            if p in request.query_params:
                if not len(request.query_params[p]):
                    return None
                if look_for in request.query_params[p]:
                    return request.query_params[p]

        # Check remote IP address
        client_ip = request.META.get('REMOTE_ADDR')
        if look_for in client_ip:
            return client_ip

        # give up
        return None

    def _find_ip_v4(self, request):
        return self.find_ip(request, ['myip', 'myipv4', 'ip'])

    def _find_ip_v6(self, request):
        return self.find_ip(request, ['myipv6', 'ipv6', 'myip', 'ip'], version=6)

    def get(self, request, *_):
        domain = self._find_domain(request)

        if domain is None:
            raise NotFound('nohost')

        ipv4 = self._find_ip_v4(request)
        ipv6 = self._find_ip_v6(request)

        data = [
            {'type': 'A', 'subname': '', 'ttl': 60, 'records': [ipv4] if ipv4 else []},
            {'type': 'AAAA', 'subname': '', 'ttl': 60, 'records': [ipv6] if ipv6 else []},
        ]

        instances = domain.rrset_set.filter(subname='', type__in=['A', 'AAAA']).all()
        serializer = serializers.RRsetSerializer(instances, domain=domain, data=data, many=True, partial=True)
        try:
            serializer.is_valid(raise_exception=True)
        except ValidationError as e:
            raise e

        with PDNSChangeTracker():
            serializer.save(domain=domain)

        return Response('good', content_type='text/plain')


class DonationList(generics.CreateAPIView):
    serializer_class = serializers.DonationSerializer

    def perform_create(self, serializer):
        iban = serializer.validated_data['iban']
        obj = serializer.save()

        def send_donation_emails(donation):
            context = {
                'donation': donation,
                'creditoridentifier': settings.SEPA['CREDITOR_ID'],
                'creditorname': settings.SEPA['CREDITOR_NAME'],
                'complete_iban': iban
            }

            # internal desec notification
            content_tmpl = get_template('emails/donation/desec-content.txt')
            subject_tmpl = get_template('emails/donation/desec-subject.txt')
            attachment_tmpl = get_template('emails/donation/desec-attachment-jameica.txt')
            from_tmpl = get_template('emails/from.txt')
            email = EmailMessage(subject_tmpl.render(context),
                                 content_tmpl.render(context),
                                 from_tmpl.render(context),
                                 ['donation@desec.io'],
                                 attachments=[
                                     ('jameica-directdebit.xml',
                                      attachment_tmpl.render(context),
                                      'text/xml')
                                 ])
            email.send()

            # donor notification
            if donation.email:
                content_tmpl = get_template('emails/donation/donor-content.txt')
                subject_tmpl = get_template('emails/donation/donor-subject.txt')
                email = EmailMessage(subject_tmpl.render(context),
                                     content_tmpl.render(context),
                                     from_tmpl.render(context),
                                     [donation.email])
                email.send()

        # send emails
        send_donation_emails(obj)


# TODO the following views have code duplication that should be put in a base class


class UserCreateView(generics.CreateAPIView):  # TODO rename 'Account....'
    serializer_class = serializers.RegisterAccountSerializer

    def create(self, request, *args, **kwargs):
        # Create user and send trigger email verification.
        # Alternative would be to create user once email is verified, but this could be abused for bulk email.

        serializer = self.get_serializer(data=request.data)
        activation_required = settings.USER_ACTIVATION_REQUIRED
        try:
            serializer.is_valid(raise_exception=True)
        except ValidationError as e:
            # Hide existing users
            email_detail = e.detail.pop('email', [])
            email_detail = [detail for detail in email_detail if detail.code != 'unique']
            if email_detail:
                e.detail['email'] = email_detail
            if e.detail:
                raise e
        else:
            ip = self.request.META.get('REMOTE_ADDR')
            user = serializer.save(is_active=(not activation_required), registration_remote_ip=ip)

            domain = serializer.validated_data.get('domain')
            if domain or activation_required:
                instance = ActivateUserAction(user=user, domain=domain)
                verification = serializers.ActivateUserSignedUserAction(instance).data
                user.send_email('activate', context=verification)

        # This request is unauthenticated, so don't expose whether we did anything.
        message = 'Welcome! Please check your mailbox.' if activation_required else 'Welcome!'
        return Response(data={'detail': message}, status=status.HTTP_202_ACCEPTED)


class SignedActionView(GenericAPIView):
    pass


class AccountView(generics.RetrieveAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = serializers.UserSerializer

    def get_object(self):
        return self.request.user


class AccountDeleteView(GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = serializers.PasswordSerializer
    # TODO this should use a different authentication class

    def get_object(self):
        # TODO is this needed?
        return self.request.user

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        action = DeleteUserAction(user=self.request.user)
        request.user.send_email('delete-user', context=serializers.DeleteUserSignedUserAction(action).data)

        # At this point, we know that we are talking to the user, so we can tell that we sent an email.
        return Response(data={'detail': 'Please check your mailbox for further account deletion instructions.'},
                        status=status.HTTP_202_ACCEPTED)


class AccountLoginView(GenericAPIView):
    serializer_class = serializers.LoginSerializer

    def post(self, request, *args, **kwargs):
        # TODO Move to authentication class?
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data.get('user')

        token = Token(user=user, name="login")
        token.save()
        user_logged_in.send(sender=user.__class__, request=self.request, user=user)

        data = serializers.TokenSerializer(token).data
        return Response(data=data, status=status.HTTP_200_OK)


class AccountChangeEmailView(GenericAPIView):
    permission_classes = (IsAuthenticated, )
    serializer_class = serializers.ChangeEmailSerializer

    def post(self, request, *args, **kwargs):
        # Check password and extract email
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        new_email = serializer.validated_data['new_email']

        verification_code = serializers.ChangeEmailSignedUserAction(
            ChangeEmailAction(user=request.user, new_email=new_email)
        ).data['verification_code']
        request.user.send_email('change-email', recipient=new_email, context={
            'verification_code': verification_code,
            'old_email': request.user.email,
            'new_email': new_email,
        })

        # At this point, we know that we are talking to the user, so we can tell that we sent an email.
        return Response(data={'detail': 'Please check your mailbox to confirm email address change.'},
                        status=status.HTTP_202_ACCEPTED)


class AccountResetPasswordView(GenericAPIView):
    serializer_class = serializers.EmailSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            email = serializer.validated_data['email']
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            pass
        else:
            action = ResetPasswordAction(user=user)
            user.send_email('reset-password', context=serializers.ChangePasswordSignedUserAction(action).data)

        # This request is unauthenticated, so don't expose whether we did anything.
        return Response(data={'detail': 'Please check your mailbox for further password reset instructions.'},
                        status=status.HTTP_202_ACCEPTED)


class VerifyView(GenericAPIView):
    authentication_classes = (auth.SignatureAuthentication,)

    def post(self, request, *args, **kwargs):
        action = kwargs.get('action')
        handler = getattr(self, 'action_%s' % action)  # TODO this may have unwanted security implications
                                                       #  URL (kwargs) action may be different from signed action
        return handler(request, *args, **kwargs)

    def action_activate(self, request, *args, **kwargs):
        serializer = serializers.ActivateUserSignedUserAction(data=request.data, context=self.get_serializer_context())
        serializer.is_valid(raise_exception=True)
        action = serializer.act()

        if not action.domain:
            return Response({
                'detail': 'Success! Please log in at {}.'.format(self.request.build_absolute_uri(reverse('v1:login')))
            })

        serializer = serializers.DomainSerializer(
            data={'name': action.domain},
            context=self.get_serializer_context()
        )
        try:
            serializer.is_valid(raise_exception=True)
        except ValidationError as e:  # e.g. domain name unavailable
            action.user.delete()
            reasons = ', '.join([detail.code for detail in e.detail.get('name', [])])
            raise ValidationError(
                f'The requested domain {action.domain} could not be registered (reason: {reasons}). '
                f'Please start over and sign up again.'
            )
        domain = PDNSChangeTracker.track(lambda: serializer.save(owner=action.user))

        if domain.parent_domain_name() in settings.LOCAL_PUBLIC_SUFFIXES:
            PDNSChangeTracker.track(lambda: DomainList.auto_delegate(domain))
            token = Token.objects.create(user=request.user, name='dyndns')
            return Response({
                # TODO wording (token vs password)
                'detail': 'Success! Here is the access token (= password) to configure your dynDNS client.',
                # TODO nested or no TokenSerializer?
                'auth_token': serializers.TokenSerializer(token).data['auth_token'],
            })
        else:
            return Response({
                # TODO add URL?
                'detail': 'Success! Please check the docs for the next steps.'
            })

    def action_change_email(self, request, *args, **kwargs):
        serializer = serializers.ChangeEmailSignedUserAction(data=request.data, context=self.get_serializer_context())
        serializer.is_valid(raise_exception=True)
        serializer.act()
        return Response({
            'detail': 'Success! Your email address has been changed.'
        })

    def action_password_reset(self, request, *args, **kwargs):
        serializer = serializers.ChangePasswordSignedUserAction(data=request.data,
                                                                context=self.get_serializer_context())
        serializer.is_valid(raise_exception=True)
        serializer.act()
        return Response({
            'detail': 'Success! Your password has been changed.'
        })

    def action_delete(self, request, *args, **kwargs):
        serializer = serializers.DeleteUserSignedUserAction(data=request.data, context=self.get_serializer_context())
        serializer.is_valid(raise_exception=True)
        serializer.act()
        return Response({
            'detail': 'All your data has been deleted. Bye bye, see you soon! <3'
        })
