import hashlib
import pickle
import time

from django.core.signing import Signer
from django.utils.crypto import constant_time_compare

PICKLE_REPR_PROTOCOL = 4


# TODO
#  the signing currently does not use the Django-provided methods for
#  signing complex data structures and also does not use the Django methods
#  for signature expiry
#  It seems that using the pickle format may have disadvantages in the scenario
#  where secret key was stolen:
#    https://docs.djangoproject.com/en/2.2/topics/signing/#protecting-complex-data-structures

def get_dict_repr(data):
    # TODO str(x) may have unexpected behavior
    #  if for some weird object type, str(x) == str(y) for x != y, str(x) should not be used for signing
    #  i.e. the security of this method depends on the str() implementation of a given object type
    #  however, str is generally not required to provide the feature we need here
    #  - maybe __hash__ or __repr__ are better choices?
    #  - just disallow the use of anything other than str?
    data_items = sorted([(str(k), str(v)) for k, v in data.items()])
    return pickle.dumps(data_items, PICKLE_REPR_PROTOCOL)


def sign(instance: dict):  # TODO rename instance to data
    # Skip password field as it was not present at signing time
    skip_fields = ['password']

    # Signature should turn invalid if these fields change
    state_attributes = {'user': ['is_active', 'email', 'password']}

    # Act on a copy of the original object
    instance = instance.copy()

    # Set timestamp if not given
    instance.setdefault('timestamp', int(time.time()))

    # TODO is this equivalent to
    #  payload = instance.copy()
    #  for field in skip_fields:
    #    payload.pop(field)
    payload = {k: v for (k, v) in instance.items() if k not in skip_fields}
    # TODO unify objects and state? (pk can be seen as 'just another model attribute')
    objects = {}  # mapping of model primary key values
    state = {}  # mapping of model attributes
    for object_field in state_attributes:  # run only once, for object_field = 'user'
        obj = payload.pop(object_field)  # removes user from payload
        objects[object_field] = getattr(obj, 'pk')
        state[object_field] = {attr: getattr(obj, attr) for attr in state_attributes[object_field]}
    state = get_dict_repr(state)  # convert state into list of tuples (using possibly unsafe str())
    state = hashlib.sha256(state).hexdigest()  # TODO can we do this primitive-independent?
    payload = get_dict_repr(payload)
    data = {'objects': objects, 'state': state, 'payload': payload}
    instance['signature'] = Signer().signature(get_dict_repr(data))
    # TODO do we have a backup of settings['SECRET_KEY']? It is not stored on any docker volume
    return instance


def verify(data):
    expected_signature = data.pop('signature')
    validated_signature = sign(data)['signature']

    return constant_time_compare(validated_signature, expected_signature)
