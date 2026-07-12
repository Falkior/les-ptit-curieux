import json
import os
from django.http import JsonResponse
from django.shortcuts import render, get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
import requests

from .models import ScanHistory

BACKEND_API_URL = os.environ.get("BACKEND_API_URL", "http://backend:5000")


def index(request):
    return render(request, "scanner/index.html")


@csrf_exempt
def start_scan(request):
    if request.method != "POST":
        return JsonResponse({"success": False, "error": "Méthode non autorisée"}, status=405)

    try:
        data = json.loads(request.body.decode("utf-8"))
    except json.JSONDecodeError:
        return JsonResponse({"success": False, "error": "JSON invalide"}, status=400)

    ip = (data.get("ip") or "").strip()
    ports = (data.get("ports") or "").strip()
    mode = (data.get("mode") or "Rapide").strip()
    modules = data.get("modules") or {
        "nmap": True,
        "smb": True,
        "ftp": True,
        "ldap": True,
    }

    if not ip:
        return JsonResponse({"success": False, "error": "Veuillez saisir une IP ou un hostname"}, status=400)

    if not any(bool(v) for v in modules.values()):
        return JsonResponse({"success": False, "error": "Aucun module sélectionné"}, status=400)

    scan = ScanHistory.objects.create(
        target=ip,
        ports=ports,
        mode=mode,
        status="running"
    )

    try:
        response = requests.post(
            f"{BACKEND_API_URL}/scan",
            json={
                "target": ip,
                "ports": ports,
                "mode": mode,
                "modules": modules
            },
            timeout=180
        )

        if response.status_code != 200:
            scan.status = "failed"
            scan.error_message = f"Erreur backend: HTTP {response.status_code} - {response.text[:1000]}"
            scan.completed_at = timezone.now()
            scan.save()

            return JsonResponse({
                "success": False,
                "error": "Erreur du backend",
                "details": response.text[:1000]
            }, status=500)

        results = response.json()

        scan.results = results
        scan.status = "completed"
        scan.completed_at = timezone.now()
        scan.save()

        return JsonResponse({
            "success": True,
            "scan_id": scan.id,
            "results": results
        })

    except requests.exceptions.Timeout:
        scan.status = "failed"
        scan.error_message = "Le scan a expiré"
        scan.completed_at = timezone.now()
        scan.save()

        return JsonResponse({
            "success": False,
            "error": "Le scan a expiré"
        }, status=504)

    except Exception as e:
        scan.status = "failed"
        scan.error_message = str(e)
        scan.completed_at = timezone.now()
        scan.save()

        return JsonResponse({
            "success": False,
            "error": f"Erreur serveur: {str(e)}"
        }, status=500)


def scan_history(request):
    scans = ScanHistory.objects.order_by("-created_at")[:20]

    data = []
    for scan in scans:
        data.append({
            "id": scan.id,
            "target": scan.target,
            "ports": scan.ports,
            "mode": scan.mode,
            "status": scan.status,
            "created_at": scan.created_at.strftime("%d/%m/%Y %H:%M:%S"),
            "completed_at": scan.completed_at.strftime("%d/%m/%Y %H:%M:%S") if scan.completed_at else None
        })

    return JsonResponse({"history": data})


def scan_detail(request, scan_id):
    scan = get_object_or_404(ScanHistory, id=scan_id)

    return JsonResponse({
        "id": scan.id,
        "target": scan.target,
        "ports": scan.ports,
        "mode": scan.mode,
        "status": scan.status,
        "results": scan.results,
        "error_message": scan.error_message,
        "created_at": scan.created_at.strftime("%d/%m/%Y %H:%M:%S"),
        "completed_at": scan.completed_at.strftime("%d/%m/%Y %H:%M:%S") if scan.completed_at else None
    })