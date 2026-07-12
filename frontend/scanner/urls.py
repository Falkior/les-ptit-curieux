from django.urls import path
from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("api/scan/", views.start_scan, name="start_scan"),
    path("api/history/", views.scan_history, name="scan_history"),
    path("api/history/<int:scan_id>/", views.scan_detail, name="scan_detail"),
]