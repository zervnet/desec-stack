import base64
import binascii
import json

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
from desecapi.models import Domain, User, RRset, Token
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
        domain = serializer.save(owner=self.request.user)

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


class DomainDetail(IdempotentDestroy, RetrieveUpdateDestroyAPIView):
    serializer_class = serializers.DomainSerializer
    permission_classes = (IsAuthenticated, IsOwner,)
    lookup_field = 'name'

    def perform_destroy(self, instance: Domain):
        with PDNSChangeTracker():
            instance.delete()
        parent_domain_name = instance.partition_name()[1]
        if parent_domain_name in settings.LOCAL_PUBLIC_SUFFIXES:
            parent_domain = Domain.objects.get(name=parent_domain_name)
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

    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        if not response.data:
            return Response(status=status.HTTP_204_NO_CONTENT)
        else:
            return response

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


class UserCreateView(generics.CreateAPIView):
    serializer_class = serializers.RegisterAccountSerializer

    def create(self, request, *args, **kwargs):
        # Create user and send trigger email verification.
        # Alternative would be to create user once email is verified, but this could be abused for bulk email.

        serializer = self.get_serializer(data=request.data)
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
            is_active = settings.USER_CREATE_VIEW_USER_IS_ACTIVE
            user = serializer.save(is_active=is_active, registration_remote_ip=ip)

            domain = serializer.validated_data.get('domain')
            if domain or not is_active:
                data = {'action': 'activate', 'user': user}
                if domain:
                    data.update({'action': 'activate-with-domain', 'domain': domain})
                verification_serializer_data = serializers.VerifySerializer(data).data
                verification_code = base64.urlsafe_b64encode(json.dumps(verification_serializer_data).encode()).decode()
                user.send_email(data['action'], context={'verification_code': verification_code})

        # This request is unauthenticated, so don't expose whether we did anything.
        return Response(data={'detail': 'Welcome! Please check your mailbox.'},
                        status=status.HTTP_202_ACCEPTED)


class AccountView(generics.RetrieveAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = serializers.UserSerializer

    def get_object(self):
        return self.request.user


class AccountDeleteView(GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = serializers.PasswordSerializer

    def get_object(self):
        return self.request.user

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        verification_serializer_data = serializers.VerifySerializer({'action': 'delete', 'user': request.user}).data
        request.user.send_email('delete-user', context={
            'verification_code': base64.urlsafe_b64encode(json.dumps(verification_serializer_data).encode()).decode()
        })

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

        verification_data = {'action': 'change-email', 'user': request.user, 'email': new_email}
        verification_serializer_data = serializers.VerifySerializer(verification_data).data
        request.user.send_email('change-email', recipient=new_email, context={
            'verification_code': base64.urlsafe_b64encode(json.dumps(verification_serializer_data).encode()).decode()
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
            verification_serializer_data = serializers.VerifySerializer({'action': 'change-password', 'user': user}).data
            user.send_email('reset-password', context={
                'verification_code': base64.urlsafe_b64encode(json.dumps(verification_serializer_data).encode()).decode()
            })

        # This request is unauthenticated, so don't expose whether we did anything.
        return Response(data={'detail': 'Please check your mailbox for further password reset instructions.'},
                        status=status.HTTP_202_ACCEPTED)


class VerifyView(GenericAPIView):
    serializer_class = serializers.VerifySerializer

    @atomic  # Do not change state in case of error, so that signature remains valid and user can try again
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)  # Move sig check to authentication class? Allows using request.user!
        error_codes = []
        try:
            user = serializer.save()
        except ValidationError as e:
            if 'domain' in e.detail:
                error_codes = [detail.code for detail in e.detail['domain']]
            else:
                raise e

        action = serializer.validated_data['action']
        if action == 'activate-with-domain':
            domain_name = serializer.validated_data['domain']
            data = {}
            if error_codes:
                data['detail'] = ('The requested domain {} could not be registered (reason: {}). '
                                  'Please start over and sign up again.'.format(domain_name, ','.join(error_codes)))
                return Response(data=data, status=status.HTTP_400_BAD_REQUEST)
            else:
                domain = Domain.objects.get(owner=user, name=domain_name)
                data['domain'] = serializers.DomainSerializer(domain).data,
                if domain_name.endswith('.dedyn.io'):
                    token = Token.objects.create(user=user, name='dyndns')
                    data['detail'] = 'Success! Here is the access token (= password) to configure your dynDNS client.'
                    data['auth_token'] = serializers.TokenSerializer(token).data['auth_token']
                else:
                    data['detail'] = 'Success! Please check the docs for the next steps.'
        else:
            details = {
                'activate': 'Success! Please log in at {}.'.format(self.request.build_absolute_uri(reverse('v1:login'))),
                'change-email': 'Success! Your email address has been changed.',
                'change-password': 'Success! Your password has been changed.',
                'delete': 'All your data has been deleted. Bye bye, see you soon! <3'
            }
            data = {'detail': details[action]}

        return Response(data=data)
