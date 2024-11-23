from django.contrib.auth.mixins import LoginRequiredMixin
from nautobot.extras.views import JobView

class JobButtonView(LoginRequiredMixin, JobView):
    def post(self, request, *args, **kwargs):
        # Only checks if the user has permission to run jobs in general
        if request.user.has_perm('extras.run_job'):
            # Proceed to run the job without checking specific object-level permissions
            return self.run_job()
        else:
            return self.permission_denied()