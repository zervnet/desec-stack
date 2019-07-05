import hashlib
import pickle
import time

from django.core.signing import Signer
from django.utils.crypto import constant_time_compare


def get_dict_repr(data):
    PICKLE_REPR_PROTOCOL = 4
    data_items = sorted([(str(k), str(v)) for k, v in data.items()])
    return pickle.dumps(data_items, PICKLE_REPR_PROTOCOL)


def sign(instance):
    # Skip password field as it was not present at signing time
    skip_fields = ['password']

    # Signature should turn invalid if these fields change
    state_attributes = {'user': ['is_active', 'email', 'password']}

    # Act on a copy of the original object
    instance = instance.copy()

    # Set timestamp if not given
    instance.setdefault('timestamp', int(time.time()))

    payload = {k: v for (k, v) in instance.items() if k not in skip_fields}
    objects = {}
    state = {}
    for object_field in state_attributes:
        obj = payload.pop(object_field)
        objects[object_field] = getattr(obj, 'pk')
        state[object_field] = {attr: getattr(obj, attr) for attr in state_attributes[object_field]}
    state = get_dict_repr(state)
    state = hashlib.sha256(state).hexdigest()
    payload = get_dict_repr(payload)
    data = {'objects': objects, 'state': state, 'payload': payload}
    instance['signature'] = Signer().signature(get_dict_repr(data))
    return instance


def verify(data):
    expected_signature = data.pop('signature')
    validated_signature = sign(data)['signature']

    return constant_time_compare(validated_signature, expected_signature)
