"""
This module tests deSEC's user management.

The tests are separated into two categories, where
(a) the client has an associated user account and
(b) does not have an associated user account.

This involves testing five separate endpoints:
(1) Registration endpoint,
(2) Reset password endpoint,
(3) Change email address endpoint,
(4) delete user endpoint, and
(5) verify endpoint.
"""
import base64
import json
import re
import time
from unittest import mock

from api import settings
from django.core import mail
from django.test import override_settings
from rest_framework import status
from rest_framework.reverse import reverse
from rest_framework.serializers import ValidationError
from rest_framework.test import APIClient

from desecapi.models import Domain, User
from desecapi.serializers import VerifySerializer
from desecapi.tests.base import DesecTestCase, PublicSuffixMockMixin


class UserManagementClient(APIClient):

    def register(self, email, password, **kwargs):
        return self.post(reverse('v1:register'), {
            'email': email,
            'password': password,
            **kwargs
        })

    def login_user(self, email, password):
        return self.post(reverse('v1:login'), {
            'email': email,
            'password': password,
        })

    def reset_password(self, email):
        return self.post(reverse('v1:account-reset-password'), {
            'email': email,
        })

    def change_email(self, token, **payload):
        return self.post(reverse('v1:account-change-email'), payload, HTTP_AUTHORIZATION='Token {}'.format(token))

    def delete_account(self, token, password):
        return self.post(reverse('v1:account-delete'), {
            'password': password
        }, HTTP_AUTHORIZATION='Token {}'.format(token))

    def view_account(self, token):
        return self.get(reverse('v1:account'), HTTP_AUTHORIZATION='Token {}'.format(token))

    def verify(self, verification_code, **kwargs):
        data = json.loads(base64.urlsafe_b64decode(verification_code.encode()).decode())
        data.update(kwargs)
        return self.post(reverse('v1:verify'), data)


class UserManagementTestCase(DesecTestCase, PublicSuffixMockMixin):

    client_class = UserManagementClient

    def register_user(self, email=None, password=None, **kwargs):
        email = email if email is not None else self.random_username()
        password = password if password is not None else self.random_password()
        return email, password, self.client.register(email, password, **kwargs)

    def login_user(self, email, password):
        response = self.client.login_user(email, password)
        token = response.data.get('auth_token')
        return token, response

    def reset_password(self, email):
        return self.client.reset_password(email)

    def change_email(self, password, new_email):
        return self.client.change_email(self.token, password=password, new_email=new_email)

    def delete_account(self, token, password):
        return self.client.delete_account(token, password)

    def verify(self, verification_code, **kwargs):
        return self.client.verify(verification_code, **kwargs)

    def assertPassword(self, email, password):
        self.assertTrue(User.objects.get(email=email).check_password(password),
                        'Expected user password to be %s, but check failed.')

    def assertUserExists(self, email):
        try:
            User.objects.get(email=email)
        except User.DoesNotExist:
            self.fail('Expected user %s to exist, but did not.' % email)

    def assertUserDoesNotExist(self, email):
        # noinspection PyTypeChecker
        with self.assertRaises(User.DoesNotExist):
            User.objects.get(email=email)

    def assertNoEmailSent(self):
        self.assertFalse(mail.outbox, "Expected no email to be sent, but %i were sent. First subject line is '%s'." %
                         (len(mail.outbox), mail.outbox[0].subject if mail.outbox else '<n/a>'))

    def assertEmailSent(self, subject_contains='', body_contains='', recipient=None, reset=True, pattern=None):
        total = 1
        self.assertEqual(len(mail.outbox), total, "Expected %i message in the outbox, but found %i." %
                         (total, len(mail.outbox)))
        email = mail.outbox[-1]
        self.assertTrue(subject_contains in email.subject,
                        "Expected '%s' in the email subject, but found '%s'" %
                        (subject_contains, email.subject))
        self.assertTrue(body_contains in email.body,
                        "Expected '%s' in the email body, but found '%s'" %
                        (body_contains, email.body))
        if recipient is not None:
            if isinstance(recipient, list):
                self.assertListEqual(recipient, email.recipients())
            else:
                self.assertIn(recipient, email.recipients())
        body = email.body
        if reset:
            mail.outbox = []
        return body if not pattern else re.search(pattern, body).group(1)

    def assertRegistrationEmail(self, recipient, reset=True):
        return self.assertEmailSent(
            subject_contains='deSEC',
            body_contains='welcome',
            recipient=[recipient],
            reset=reset,
            pattern=r'verification code: ([^\s]*)',
        )

    def assertResetPasswordEmail(self, recipient, reset=True):
        return self.assertEmailSent(
            subject_contains='Password reset',
            body_contains='verification code',
            recipient=[recipient],
            reset=reset,
            pattern=r'verification code: ([^\s]*)',
        )

    def assertChangeEmailVerificationEmail(self, recipient, reset=True):
        return self.assertEmailSent(
            subject_contains='Confirmation required: Email address change',
            body_contains='verification code',
            recipient=[recipient],
            reset=reset,
            pattern=r'verification code: ([^\s]*)',
        )

    def assertChangeEmailNotificationEmail(self, recipient, reset=True):
        return self.assertEmailSent(
            subject_contains='Account email address changed',
            body_contains='email address of your deSEC account has been changed to another address.',
            recipient=[recipient],
            reset=reset,
        )

    def assertDeleteAccountEmail(self, recipient, reset=True):
        return self.assertEmailSent(
            subject_contains='Confirmation required: Delete account',
            body_contains='verification code',
            recipient=[recipient],
            reset=reset,
            pattern=r'verification code: ([^\s]*)',
        )

    def assertRegistrationSuccessResponse(self, response):
        return self.assertContains(
            response=response,
            text="Welcome! Please check your mailbox.",
            status_code=status.HTTP_202_ACCEPTED
        )

    def assertLoginSuccessResponse(self, response):
        return self.assertContains(
            response=response,
            text="auth_token",
            status_code=status.HTTP_200_OK
        )

    def assertRegistrationFailurePasswordRequiredResponse(self, response):
        self.assertContains(
            response=response,
            text="This field may not be blank",
            status_code=status.HTTP_400_BAD_REQUEST
        )
        self.assertEqual(response.data['password'][0].code, 'blank')

    def assertRegistrationFailureDomainUnavailableResponse(self, response, domain, reason):
        self.assertContains(
            response=response,
            text=("The requested domain {} could not be registered (reason: {}). "
                  "Please start over and sign up again.".format(domain, reason)),
            status_code=status.HTTP_400_BAD_REQUEST
        )

    def assertRegistrationVerificationSuccessResponse(self, response):
        return self.assertContains(
            response=response,
            text="Success! Please log in at",
            status_code=status.HTTP_200_OK
        )

    def assertRegistrationWithDomainVerificationSuccessResponse(self, response, domain=None):
        if domain and domain.endswith('.dedyn.io'):
            text = 'Success! Here is the access token (= password) to configure your dynDNS client.'
        else:
            text = 'Success! Please check the docs for the next steps.'
        return self.assertContains(
            response=response,
            text=text,
            status_code=status.HTTP_200_OK
        )

    def assertResetPasswordSuccessResponse(self, response):
        return self.assertContains(
            response=response,
            text="Please check your mailbox for further password reset instructions.",
            status_code=status.HTTP_202_ACCEPTED
        )

    def assertResetPasswordVerificationSuccessResponse(self, response):
        return self.assertContains(
            response=response,
            text="Success! Your password has been changed.",
            status_code=status.HTTP_200_OK
        )

    def assertChangeEmailSuccessResponse(self, response):
        return self.assertContains(
            response=response,
            text="Please check your mailbox to confirm email address change.",
            status_code=status.HTTP_202_ACCEPTED
        )

    def assert401InvalidPasswordResponse(self, response):
        return self.assertContains(
            response=response,
            text="Invalid password.",
            status_code=status.HTTP_401_UNAUTHORIZED
        )

    def assertChangeEmailFailureAddressTakenResponse(self, response):
        return self.assertContains(
            response=response,
            text="You already have another account with this email address.",
            status_code=status.HTTP_400_BAD_REQUEST
        )

    def assertChangeEmailFailureSameAddressResponse(self, response):
        return self.assertContains(
            response=response,
            text="Email address unchanged.",
            status_code=status.HTTP_400_BAD_REQUEST
        )

    def assertChangeEmailVerificationSuccessResponse(self, response):
        return self.assertContains(
            response=response,
            text="Success! Your email address has been changed.",
            status_code=status.HTTP_200_OK
        )

    def assertChangeEmailVerificationFailureChangePasswordResponse(self, response):
        return self.assertContains(
            response=response,
            text="This field is not allowed for action ",
            status_code=status.HTTP_400_BAD_REQUEST
        )

    def assertDeleteAccountSuccessResponse(self, response):
        return self.assertContains(
            response=response,
            text="Please check your mailbox for further account deletion instructions.",
            status_code=status.HTTP_202_ACCEPTED
        )

    def assertDeleteAccountVerificationSuccessResponse(self, response):
        return self.assertContains(
            response=response,
            text="All your data has been deleted. Bye bye, see you soon! <3",
            status_code=status.HTTP_200_OK
        )

    def assertVerificationFailureInvalidCodeResponse(self, response):
        return self.assertContains(
            response=response,
            text="Bad signature.",
            status_code=status.HTTP_400_BAD_REQUEST
        )

    def assertVerificationFailureUnknownUserResponse(self, response):
        return self.assertContains(
            response=response,
            text="This user does not exist.",
            status_code=status.HTTP_400_BAD_REQUEST
        )

    def _test_registration(self, email=None, password=None, **kwargs):
        email, password, response = self.register_user(email, password, **kwargs)
        self.assertRegistrationSuccessResponse(response)
        self.assertUserExists(email)
        self.assertFalse(User.objects.get(email=email).is_active)
        self.assertPassword(email, password)
        verification_code = self.assertRegistrationEmail(email)
        self.assertRegistrationVerificationSuccessResponse(self.verify(verification_code))
        self.assertTrue(User.objects.get(email=email).is_active)
        self.assertPassword(email, password)
        return email, password

    def _test_registration_with_domain(self, email=None, password=None, domain=None, expect_failure_reason=None):
        domain = domain or self.random_domain_name()

        email, password, response = self.register_user(email, password, domain=domain)
        self.assertRegistrationSuccessResponse(response)
        self.assertUserExists(email)
        self.assertFalse(User.objects.get(email=email).is_active)
        self.assertPassword(email, password)

        verification_code = self.assertRegistrationEmail(email)
        if expect_failure_reason is None:
            if domain.endswith('.dedyn.io'):
                cm = self.requests_desec_domain_creation_auto_delegation(domain)
            else:
                cm = self.requests_desec_domain_creation(domain)
            with self.assertPdnsRequests(cm):
                response = self.verify(verification_code)
            self.assertRegistrationWithDomainVerificationSuccessResponse(response, domain)
            self.assertTrue(User.objects.get(email=email).is_active)
            self.assertPassword(email, password)
            self.assertTrue(Domain.objects.filter(name=domain, owner__email=email).exists())
            return email, password, domain
        else:
            domain_exists = Domain.objects.filter(name=domain).exists()
            response = self.verify(verification_code)
            self.assertRegistrationFailureDomainUnavailableResponse(response, domain, expect_failure_reason)
            self.assertFalse(User.objects.filter(email=email).exists())
            self.assertEqual(Domain.objects.filter(name=domain).exists(), domain_exists)

    def _test_login(self):
        token, response = self.login_user(self.email, self.password)
        self.assertLoginSuccessResponse(response)
        return token

    def _test_reset_password(self, email, new_password=None):
        new_password = new_password or self.random_password()
        self.assertResetPasswordSuccessResponse(self.reset_password(email))
        verification_code = self.assertResetPasswordEmail(email)
        self.assertResetPasswordVerificationSuccessResponse(self.verify(verification_code, password=new_password))
        self.assertPassword(email, new_password)
        return new_password

    def _test_change_email(self, password):
        old_email = self.email
        new_email = self.random_username()
        self.assertChangeEmailSuccessResponse(self.change_email(password, new_email))
        verification_code = self.assertChangeEmailVerificationEmail(new_email)
        self.assertChangeEmailVerificationSuccessResponse(self.verify(verification_code))
        self.assertChangeEmailNotificationEmail(old_email)
        self.assertUserExists(new_email)
        self.assertUserDoesNotExist(old_email)
        self.email = new_email
        return self.email

    def _test_delete_account(self, email, password, token):
        self.assertDeleteAccountSuccessResponse(self.delete_account(token, password))
        verification_code = self.assertDeleteAccountEmail(email)
        self.assertDeleteAccountVerificationSuccessResponse(self.verify(verification_code))
        self.assertUserDoesNotExist(email)


class UserLifeCycleTestCase(UserManagementTestCase):

    def test_life_cycle(self):
        self.email, self.password = self._test_registration()
        self.password = self._test_reset_password(self.email)
        mail.outbox = []
        self.token = self._test_login()
        email = self._test_change_email(self.password)
        self._test_delete_account(email, self.password, self.token)


class NoUserAccountTestCase(UserLifeCycleTestCase):

    def test_registration(self):
        self._test_registration()

    def test_registration_with_domain(self):
        PublicSuffixMockMixin.setUpMockPatch(self)
        with self.get_psl_context_manager('.'):
            _, _, domain = self._test_registration_with_domain()
            self._test_registration_with_domain(domain=domain, expect_failure_reason='unique')
            self._test_registration_with_domain(domain='töö--', expect_failure_reason='invalid_domain_name')

        with self.get_psl_context_manager('co.uk'):
            self._test_registration_with_domain(domain='co.uk', expect_failure_reason='name_unavailable')
        with self.get_psl_context_manager('dedyn.io'):
            self._test_registration_with_domain(domain=self.random_domain_name(suffix='dedyn.io'))

    def test_registration_known_account(self):
        email, _ = self._test_registration()
        self.assertRegistrationSuccessResponse(self.register_user(email, self.random_password())[2])
        self.assertNoEmailSent()

    def test_registration_password_required(self):
        email = self.random_username()
        self.assertRegistrationFailurePasswordRequiredResponse(
            response=self.register_user(email=email, password='')[2]
        )
        self.assertNoEmailSent()
        self.assertUserDoesNotExist(email)

    def test_registration_spam_protection(self):
        email = self.random_username()
        self.assertRegistrationSuccessResponse(
            response=self.register_user(email=email)[2]
        )
        self.assertRegistrationEmail(email)
        for _ in range(5):
            self.assertRegistrationSuccessResponse(
                response=self.register_user(email=email)[2]
            )
            self.assertNoEmailSent()


class OtherUserAccountTestCase(UserManagementTestCase):

    def setUp(self):
        super().setUp()
        self.other_email, self.other_password = self._test_registration()

    def test_reset_password_unknown_user(self):
        # TODO this does not account for timing side-channel information
        self.assertResetPasswordSuccessResponse(
            response=self.reset_password(self.random_username())
        )
        self.assertNoEmailSent()


class HasUserAccountTestCase(UserManagementTestCase):

    def __init__(self, methodName: str = ...) -> None:
        super().__init__(methodName)
        self.email = None
        self.password = None

    def setUp(self):
        super().setUp()
        self.email, self.password = self._test_registration()
        self.token = self._test_login()

    def _start_reset_password(self):
        self.assertResetPasswordSuccessResponse(
            response=self.reset_password(self.email)
        )
        return self.assertResetPasswordEmail(self.email)

    def _start_change_email(self):
        new_email = self.random_username()
        self.assertChangeEmailSuccessResponse(
            response=self.change_email(self.password, new_email)
        )
        return self.assertChangeEmailVerificationEmail(new_email), new_email

    def _start_delete_account(self):
        self.assertDeleteAccountSuccessResponse(self.delete_account(self.token, self.password))
        return self.assertDeleteAccountEmail(self.email)

    def _finish_reset_password(self, verification_code, expect_success=True):
        new_password = self.random_password()
        response = self.verify(verification_code, password=new_password)
        if expect_success:
            self.assertResetPasswordVerificationSuccessResponse(response=response)
        else:
            self.assertVerificationFailureInvalidCodeResponse(response)
        return new_password

    def _finish_change_email(self, verification_code, expect_success=True):
        response = self.verify(verification_code)
        if expect_success:
            self.assertChangeEmailVerificationSuccessResponse(response)
            self.assertChangeEmailNotificationEmail(self.email)
        else:
            self.assertVerificationFailureInvalidCodeResponse(response)

    def _finish_delete_account(self, verification_code):
        self.assertDeleteAccountVerificationSuccessResponse(self.verify(verification_code))
        self.assertUserDoesNotExist(self.email)

    def test_view_account(self):
        response = self.client.view_account(self.token)
        self.assertEqual(response.status_code, 200)
        self.assertTrue('created' in response.data)
        self.assertEqual(response.data['email'], self.email)
        self.assertEqual(response.data['id'], User.objects.get(email=self.email).pk)
        self.assertEqual(response.data['limit_domains'], settings.LIMIT_USER_DOMAIN_COUNT_DEFAULT)

    def test_reset_password(self):
        self._test_reset_password(self.email)

    def test_reset_password_multiple_times(self):
        for _ in range(3):
            self._test_reset_password(self.email)
            mail.outbox = []

    def test_reset_password_during_change_email_interleaved(self):
        reset_password_verification_code = self._start_reset_password()
        change_email_verification_code, new_email = self._start_change_email()
        new_password = self._finish_reset_password(reset_password_verification_code)
        self._finish_change_email(change_email_verification_code, expect_success=False)

        self.assertUserExists(self.email)
        self.assertUserDoesNotExist(new_email)
        self.assertPassword(self.email, new_password)

    def test_reset_password_during_change_email_nested(self):
        change_email_verification_code, new_email = self._start_change_email()
        reset_password_verification_code = self._start_reset_password()
        new_password = self._finish_reset_password(reset_password_verification_code)
        self._finish_change_email(change_email_verification_code, expect_success=False)

        self.assertUserExists(self.email)
        self.assertUserDoesNotExist(new_email)
        self.assertPassword(self.email, new_password)

    def test_reset_password_validation_unknown_user(self):
        verification_code = self._start_reset_password()
        self._test_delete_account(self.email, self.password, self.token)
        self.assertVerificationFailureUnknownUserResponse(
            response=self.verify(verification_code)
        )
        self.assertNoEmailSent()

    def test_change_email(self):
        self._test_change_email(self.password)

    def test_change_email_requires_password(self):
        # Make sure that the account's email address cannot be changed with a token alone (password required)
        new_email = self.random_username()
        response = self.client.change_email(self.token, new_email=new_email)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['password'][0].code, 'required')
        self.assertNoEmailSent()

    def test_change_email_multiple_times(self):
        for _ in range(3):
            self._test_change_email(self.password)

    def test_change_email_user_exists(self):
        known_email, _ = self._test_registration()
        # We send a verification link to the new email and check account existence only later, upon verification
        self.assertChangeEmailSuccessResponse(
            response=self.change_email(self.password, known_email)
        )

    def test_change_email_verification_user_exists(self):
        new_email = self.random_username()
        self.assertChangeEmailSuccessResponse(self.change_email(self.password, new_email))
        verification_code = self.assertChangeEmailVerificationEmail(new_email)
        new_email, new_password = self._test_registration(new_email)
        self.assertChangeEmailFailureAddressTakenResponse(
            response=self.verify(verification_code)
        )
        self.assertUserExists(self.email)
        self.assertPassword(self.email, self.password)
        self.assertUserExists(new_email)
        self.assertPassword(new_email, new_password)

    def test_change_email_verification_change_password(self):
        new_email = self.random_username()
        self.assertChangeEmailSuccessResponse(self.change_email(self.password, new_email))
        verification_code = self.assertChangeEmailVerificationEmail(new_email)
        self.assertChangeEmailVerificationFailureChangePasswordResponse(
            response=self.verify(verification_code, password=self.random_password())
        )
        self.assertUserExists(self.email)
        self.assertUserDoesNotExist(new_email)
        self.assertPassword(self.email, self.password)
        self.assertChangeEmailVerificationSuccessResponse(
            response=self.verify(verification_code)
        )
        self.assertUserDoesNotExist(self.email)
        self.assertUserExists(new_email)
        self.assertPassword(new_email, self.password)

    def test_change_email_same_email(self):
        self.assertChangeEmailFailureSameAddressResponse(
            response=self.change_email(self.password, self.email)
        )
        self.assertUserExists(self.email)

    def test_change_email_during_reset_password_interleaved(self):
        change_email_verification_code, new_email = self._start_change_email()
        reset_password_verification_code = self._start_reset_password()
        self._finish_change_email(change_email_verification_code)
        self._finish_reset_password(reset_password_verification_code, expect_success=False)

        self.assertUserExists(new_email)
        self.assertUserDoesNotExist(self.email)
        self.assertPassword(new_email, self.password)

    def test_change_email_during_reset_password_nested(self):
        reset_password_verification_code = self._start_reset_password()
        change_email_verification_code, new_email = self._start_change_email()
        self._finish_change_email(change_email_verification_code)
        self._finish_reset_password(reset_password_verification_code, expect_success=False)

        self.assertUserExists(new_email)
        self.assertUserDoesNotExist(self.email)
        self.assertPassword(new_email, self.password)

    def test_change_email_nested(self):
        verification_code_1, new_email_1 = self._start_change_email()
        verification_code_2, new_email_2 = self._start_change_email()

        self._finish_change_email(verification_code_2)
        self.assertUserDoesNotExist(self.email)
        self.assertUserDoesNotExist(new_email_1)
        self.assertUserExists(new_email_2)

        self._finish_change_email(verification_code_1, expect_success=False)
        self.assertUserDoesNotExist(self.email)
        self.assertUserDoesNotExist(new_email_1)
        self.assertUserExists(new_email_2)

    def test_change_email_interleaved(self):
        verification_code_1, new_email_1 = self._start_change_email()
        verification_code_2, new_email_2 = self._start_change_email()

        self._finish_change_email(verification_code_1)
        self.assertUserDoesNotExist(self.email)
        self.assertUserExists(new_email_1)
        self.assertUserDoesNotExist(new_email_2)

        self._finish_change_email(verification_code_2, expect_success=False)
        self.assertUserDoesNotExist(self.email)
        self.assertUserExists(new_email_1)
        self.assertUserDoesNotExist(new_email_2)

    def test_change_email_validation_unknown_user(self):
        verification_code, new_email = self._start_change_email()
        self._test_delete_account(self.email, self.password, self.token)
        self.assertVerificationFailureUnknownUserResponse(
            response=self.verify(verification_code)
        )
        self.assertNoEmailSent()

    def test_delete_account_validation_unknown_user(self):
        verification_code = self._start_delete_account()
        self._test_delete_account(self.email, self.password, self.token)
        self.assertVerificationFailureUnknownUserResponse(
            response=self.verify(verification_code)
        )
        self.assertNoEmailSent()


class VerifySerializerTestCase(DesecTestCase):

    def setUp(self):
        super().setUp()
        self.user = self.create_user()

    def test_signature_varies_by_secret(self):
        data = {'user': self.user, 'action': 'test', 'timestamp': int(time.time())}
        secrets = [
            '#0ka!t#6%28imjz+2t%l(()yu)tg93-1w%$du0*po)*@l+@+4h',
            'feb7tjud7m=91$^mrk8dq&nz(0^!6+1xk)%gum#oe%(n)8jic7',
        ]

        signatures = []
        for secret in secrets:
            with override_settings(SECRET_KEY=secret):
                serializer_data1 = VerifySerializer(data).data
                serializer_data2 = VerifySerializer(data).data
                self.assertEqual(serializer_data1['signature'], serializer_data2['signature'])
                signatures.append(serializer_data1['signature'])

        self.assertTrue(len(set(signatures)) == len(secrets))

    def test_missing_fields(self):
        serializer = VerifySerializer(data={})
        with self.assertRaises(ValidationError) as cm:
            serializer.is_valid(raise_exception=True)
        self.assertTrue(all(all(item.code == 'required' for item in field_detail)
                            for field_detail in cm.exception.detail.values()))
        self.assertEqual(cm.exception.detail.keys(), {'action', 'user', 'signature', 'timestamp'})

    def test_fake_action(self):
        data = {'user': self.user, 'action': 'activate'}
        serializer_data = VerifySerializer(data).data

        serializer = VerifySerializer(data=serializer_data)
        serializer.is_valid(raise_exception=True)

        serializer_data['action'] = 'test'
        serializer = VerifySerializer(data=serializer_data)
        with self.assertRaises(ValidationError):
            serializer.is_valid(raise_exception=True)

    def test_fake_email(self):
        data = {'user': self.user, 'action': 'change-email', 'email': self.random_username()}
        serializer_data = VerifySerializer(data).data

        serializer = VerifySerializer(data=serializer_data)
        serializer.is_valid(raise_exception=True)

        serializer_data['email'] = self.random_username()
        serializer = VerifySerializer(data=serializer_data)
        with self.assertRaises(ValidationError) as cm:
            serializer.is_valid(raise_exception=True)

        self.assertEqual(cm.exception.detail['non_field_errors'][0].code, 'invalid')
        self.assertEqual(cm.exception.detail['non_field_errors'][0], 'Bad signature.')

    def test_fake_timestamp(self):
        data = {'user': self.user, 'action': 'delete', 'timestamp': int(time.time())}
        serializer_data = VerifySerializer(data).data

        serializer = VerifySerializer(data=serializer_data)
        serializer.is_valid(raise_exception=True)

        serializer_data['timestamp'] += 1
        serializer = VerifySerializer(data=serializer_data)
        with self.assertRaises(ValidationError) as cm:
            serializer.is_valid(raise_exception=True)

        self.assertEqual(cm.exception.detail['non_field_errors'][0].code, 'invalid')
        self.assertEqual(cm.exception.detail['non_field_errors'][0], 'Bad signature.')

    def test_fake_signature(self):
        data = {'user': self.user, 'action': 'activate'}
        serializer_data = VerifySerializer(data).data

        serializer = VerifySerializer(data=serializer_data)
        serializer.is_valid(raise_exception=True)

        serializer_data['signature'] = serializer_data['signature'][::-1]  # Reverse
        serializer = VerifySerializer(data=serializer_data)
        with self.assertRaises(ValidationError) as cm:
            serializer.is_valid(raise_exception=True)

        self.assertEqual(cm.exception.detail['non_field_errors'][0].code, 'invalid')
        self.assertEqual(cm.exception.detail['non_field_errors'][0], 'Bad signature.')

    def test_fake_user(self):
        data = {'user': self.user, 'action': 'activate'}
        serializer_data = VerifySerializer(data).data

        serializer = VerifySerializer(data=serializer_data)
        serializer.is_valid(raise_exception=True)

        user = self.create_user()
        serializer_data['user'] = user.pk
        serializer = VerifySerializer(data=serializer_data)
        with self.assertRaises(ValidationError) as cm:
            serializer.is_valid(raise_exception=True)
        self.assertEqual(cm.exception.detail['non_field_errors'][0].code, 'invalid')
        self.assertEqual(cm.exception.detail['non_field_errors'][0], 'Bad signature.')

        user.delete()
        serializer = VerifySerializer(data=serializer_data)
        with self.assertRaises(ValidationError) as cm:
            serializer.is_valid(raise_exception=True)
        self.assertEqual(cm.exception.detail['user'][0].code, 'does_not_exist')

    def test_expired(self):
        mock_time = mock.Mock()

        @mock.patch('time.time', mock_time)
        def _construct_expired_serializer_data(data):
            return VerifySerializer(data).data

        def _run(delay):
            mock_time.return_value = time.time() - settings.VALIDITY_PERIOD_VERIFICATION_SIGNATURE + delay

            data = {'user': self.user, 'action': 'activate'}
            serializer_data = _construct_expired_serializer_data(data)
            serializer = VerifySerializer(data=serializer_data)

            if delay >= 0:
                serializer.is_valid(raise_exception=True)
                return True
            else:
                with self.assertRaises(ValidationError) as cm:
                    serializer.is_valid(raise_exception=True)
                self.assertEqual(cm.exception.detail['timestamp'][0].code, 'invalid')
                self.assertEqual(cm.exception.detail['timestamp'][0], 'Expired.')
                return False

        failed_delays = set()
        for delay in [-1, 0, 1]:
            success = _run(delay)
            if not success:
                failed_delays.add(delay)

        self.assertEquals(failed_delays, {-1})
