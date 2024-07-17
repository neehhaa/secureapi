import uuid

from django.http import JsonResponse
from django.views import View
import json
from .utils import generate_aes_key, get_timestamp_and_ivector, encrypt_payload, encrypt_aes_key, decrypt_aes_key, \
    decrypt_payload


class SecureAPIView(View):
    def post(self, request):
        # Parse incoming request
        data = json.loads(request.body)
        payload = data.get('payload')

        # Generate AES key and timestamp
        aes_secret_key_b64, aes_secret_key = generate_aes_key()
        timestamp, ivector = get_timestamp_and_ivector()

        # Encrypt payload
        encrypted_payload = encrypt_payload(payload, aes_secret_key, ivector)

        # Encrypt AES key with server's public key
        public_key_path = 'path/to/server_public_key.pem'
        encrypted_aes_secret_key_b64 = encrypt_aes_key(aes_secret_key, public_key_path)

        # Prepare the request
        request_data = {
            "metadata": {
                "secretId": encrypted_aes_secret_key_b64,
                "version": "V1.0",
                "timestamp": timestamp,
                "requestId": str(uuid.uuid4())
            },
            "payload": encrypted_payload
        }

        # Return the encrypted request
        return JsonResponse(request_data)

    def get(self, request):
        # Example response handling
        data = {
            "metadata": {
                "secretId": "encrypted_secret_key_b64",
                "version": "V1.0",
                "timestamp": "timestamp",
                "requestId": "unique_request_id"
            },
            "payload": "encrypted_response_payload"
        }

        private_key_path = 'path/to/private_key.pem'
        encrypted_aes_key_b64 = data["metadata"]["secretId"]
        decrypted_aes_secret_key = decrypt_aes_key(encrypted_aes_key_b64, private_key_path)
        ivector = data["metadata"]["timestamp"][:16].encode('utf-8')
        decrypted_payload = decrypt_payload(data["payload"], decrypted_aes_secret_key, ivector)

        response_data = {
            "decrypted_payload": decrypted_payload
        }

        return JsonResponse(response_data)
