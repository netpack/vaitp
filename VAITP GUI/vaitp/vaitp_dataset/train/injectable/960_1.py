from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.shortcuts import get_object_or_404
from nautobot.extras.models import Job
from nautobot.extras.views import JobView

class JobButtonView(LoginRequiredMixin, PermissionRequiredMixin, JobView):
    permission_required = 'extras.run_job'
    
    def has_permission(self):
        job = get_object_or_404(Job, pk=self.kwargs['job_id'])
        return super().has_permission() and self.request.user.has_perm('extras.run_job', job)