from django.contrib import admin
from .models import ScanHistory

@admin.register(ScanHistory)
class ScanHistoryAdmin(admin.ModelAdmin):
    list_display = ('target', 'mode', 'status', 'created_at')
    list_filter = ('status', 'mode', 'created_at')
    search_fields = ('target',)
    readonly_fields = ('created_at', 'completed_at')
