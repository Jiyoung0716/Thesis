# For handling ZAP's High severity (CSP Header Not Set (HIGH))

class CSPMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        # If needed, policy can modify more difficult
        response["Content-Security-Policy"] = "default-src 'self'"
        return response
