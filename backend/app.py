from flask import Flask, request, jsonify
from flask_cors import CORS
import ipaddress
import re
import subprocess
import ftplib
import socket
import nmap

app = Flask(__name__)
CORS(app)


AUTH_PORT_MAP = {
    "ssh": [22],
    "ftp": [21],
    "smb": [139, 445],
    "ldap": [389, 636],
    "rdp": [3389],
    "mysql": [3306],
    "postgresql": [5432],
    "mssql": [1433],
    "smtp": [25, 465, 587],
    "imap": [143, 993],
    "pop3": [110, 995],
    "http": [80, 8080, 8000],
    "https": [443, 8443],
}


def validate_target(target: str) -> bool:
    if not target or not isinstance(target, str):
        return False

    target = target.strip()

    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    hostname_regex = r"^(?=.{1,253}$)(?!-)[A-Za-z0-9.-]+(?<!-)$"
    return re.match(hostname_regex, target) is not None


def normalize_mode(mode: str) -> str:
    if not mode:
        return "Rapide"
    mode = mode.strip()
    if mode.lower() == "rapide":
        return "Rapide"
    if mode.lower() == "complet":
        return "Complet"
    return "Rapide"


def normalize_modules(modules) -> dict:
    default = {
        "nmap": True,
        "smb": True,
        "ftp": True,
        "ldap": True,
    }

    if not isinstance(modules, dict):
        return default

    normalized = {}
    for key in default:
        normalized[key] = bool(modules.get(key, False))
    return normalized


def build_nmap_arguments(mode: str, ports: str) -> str:
    mode = normalize_mode(mode)

    if mode == "Rapide":
        if ports:
            return f"-Pn -T4 -p {ports}"
        return "-Pn -T4 -F"

    if mode == "Complet":
        if ports:
            return f"-Pn -T4 -sV -p {ports}"
        return "-Pn -T4 -sV -p-"

    if ports:
        return f"-Pn -T4 -sV -p {ports}"
    return "-Pn -T4 -sV"


def scan_with_nmap_python(target: str, ports: str, mode: str) -> dict:
    nm = nmap.PortScanner()
    arguments = build_nmap_arguments(mode, ports)

    results = {
        "arguments": arguments,
        "hosts": {},
        "ports": {},
        "open_ports": [],
        "errors": []
    }

    try:
        nm.scan(hosts=target, arguments=arguments)

        for host in nm.all_hosts():
            host_info = {
                "state": nm[host].state() if "status" in nm[host] else "unknown",
                "hostnames": nm[host].hostnames() if hasattr(nm[host], "hostnames") else [],
                "protocols": {}
            }

            for proto in nm[host].all_protocols():
                host_info["protocols"][proto] = {}

                ports_list = sorted(nm[host][proto].keys())
                for port in ports_list:
                    port_data = nm[host][proto][port]
                    entry = {
                        "state": port_data.get("state", "unknown"),
                        "service": port_data.get("name", "unknown"),
                        "product": port_data.get("product", ""),
                        "version": port_data.get("version", ""),
                        "extrainfo": port_data.get("extrainfo", ""),
                        "reason": port_data.get("reason", "")
                    }

                    host_info["protocols"][proto][str(port)] = entry
                    results["ports"][str(port)] = entry

                    if entry["state"] == "open":
                        results["open_ports"].append({
                            "port": port,
                            "protocol": proto,
                            "service": entry["service"]
                        })

            results["hosts"][host] = host_info

        return results

    except Exception as e:
        results["errors"].append(str(e))
        return results


def run_command(command, timeout=20):
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        ok = completed.returncode == 0
        return ok, completed.stdout.strip(), completed.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "Commande expirée"
    except Exception as e:
        return False, "", str(e)


def parse_smb_shares(output: str) -> list:
    shares = []
    lines = output.splitlines()

    in_share_section = False
    for line in lines:
        stripped = line.strip()

        if "Sharename" in stripped and "Type" in stripped:
            in_share_section = True
            continue

        if in_share_section:
            if not stripped or stripped.startswith("Server") or stripped.startswith("Workgroup"):
                continue

            if stripped.startswith("----"):
                continue

            parts = stripped.split()
            if parts:
                name = parts[0]
                if name not in shares:
                    shares.append(name)

    return shares


def check_smb_anonymous(target: str) -> dict:
    command = ["smbclient", "-p 1445", "-L", f"//{target}", "-N", "-g"]
    ok, stdout, stderr = run_command(command, timeout=20)

    combined = "\n".join([part for part in [stdout, stderr] if part]).strip()
    shares = parse_smb_shares(combined)

    allowed = False
    message = "Accès anonyme refusé"

    if shares:
        allowed = True
        message = "Accès anonyme autorisé"
    elif ok and "NT_STATUS" not in combined:
        allowed = True
        message = "Accès anonyme probablement autorisé"

    return {
        "allowed": allowed,
        "shares": shares,
        "message": message,
        "raw_output": combined[:4000]
    }


def check_ftp_anonymous(target: str) -> dict:
    ftp = None
    try:
        ftp = ftplib.FTP()
        ftp.connect(target, 21, timeout=10)
        ftp.login("anonymous", "anonymous@example.com")

        entries = []
        try:
            entries = ftp.nlst()
        except Exception:
            pass

        return {
            "allowed": True,
            "message": "Connexion anonyme autorisée",
            "entries": entries[:50]
        }

    except (socket.timeout, ConnectionRefusedError):
        return {
            "allowed": False,
            "message": "Service FTP indisponible ou port fermé",
            "entries": []
        }
    except ftplib.error_perm as e:
        return {
            "allowed": False,
            "message": f"Connexion anonyme refusée: {str(e)}",
            "entries": []
        }
    except Exception as e:
        return {
            "allowed": False,
            "message": f"Erreur FTP: {str(e)}",
            "entries": []
        }
    finally:
        try:
            if ftp:
                ftp.quit()
        except Exception:
            pass


def check_ldap_anonymous(target: str) -> dict:
    command = [
        "ldapsearch",
        "-H", f"ldap://{target}",
        "-x",
        "-b", "",
        "-s", "base"
    ]

    ok, stdout, stderr = run_command(command, timeout=20)
    combined = "\n".join([part for part in [stdout, stderr] if part]).strip()

    allowed = False
    naming_contexts = []

    if "namingContexts:" in combined or "supportedLDAPVersion:" in combined or "dn:" in combined:
        allowed = True
        for line in combined.splitlines():
            if line.startswith("namingContexts:"):
                naming_contexts.append(line.split(":", 1)[1].strip())

    return {
        "allowed": allowed,
        "message": "Bind anonyme autorisé" if allowed else "Bind anonyme refusé ou service indisponible",
        "naming_contexts": naming_contexts,
        "raw_output": combined[:4000]
    }


def get_open_port_numbers(nmap_result: dict) -> list:
    if not nmap_result:
        return []

    ports = []
    for port_str, info in (nmap_result.get("ports") or {}).items():
        try:
            if info.get("state") == "open":
                ports.append(int(port_str))
        except ValueError:
            continue
    return sorted(set(ports))


def detect_auth_surface(nmap_result: dict) -> dict:
    open_ports = get_open_port_numbers(nmap_result)

    detected = {}
    for service_name, service_ports in AUTH_PORT_MAP.items():
        matched_ports = [p for p in service_ports if p in open_ports]
        if matched_ports:
            detected[service_name] = {
                "detected": True,
                "ports": matched_ports
            }

    services = []
    for name, data in detected.items():
        services.append({
            "service": name,
            "ports": data["ports"]
        })

    return {
        "open_auth_ports": open_ports,
        "services": services,
        "detected": detected
    }


def should_run_module(module_name: str, modules: dict, nmap_result: dict) -> tuple[bool, str]:
    if not modules.get(module_name, False):
        return False, "module non sélectionné"

    if not nmap_result:
        return True, "nmap non exécuté, test lancé directement"

    open_ports = get_open_port_numbers(nmap_result)

    if module_name == "smb":
        if any(p in open_ports for p in [139, 445, 1445]):
            return True, "port SMB détecté"
        return False, "aucun port SMB ouvert détecté"

    if module_name == "ftp":
        if 21 in open_ports:
            return True, "port FTP détecté"
        return False, "aucun port FTP ouvert détecté"

    if module_name == "ldap":
        if any(p in open_ports for p in [389, 636]):
            return True, "port LDAP détecté"
        return False, "aucun port LDAP ouvert détecté"

    return True, "module autorisé"


def build_summary(nmap_result, smb_result, ftp_result, ldap_result, modules) -> dict:
    summary = {
        "open_ports_count": 0,
        "smb_anonymous": False,
        "ftp_anonymous": False,
        "ldap_anonymous": False,
    }

    if modules.get("nmap") and nmap_result:
        ports = nmap_result.get("ports", {})
        summary["open_ports_count"] = sum(1 for info in ports.values() if info.get("state") == "open")

    if smb_result and smb_result.get("executed"):
        summary["smb_anonymous"] = smb_result.get("allowed", False)

    if ftp_result and ftp_result.get("executed"):
        summary["ftp_anonymous"] = ftp_result.get("allowed", False)

    if ldap_result and ldap_result.get("executed"):
        summary["ldap_anonymous"] = ldap_result.get("allowed", False)

    return summary


def build_risk_assessment(nmap_result, smb_result, ftp_result, ldap_result, auth_surface) -> dict:
    findings = []
    score = 0

    open_ports = get_open_port_numbers(nmap_result) if nmap_result else []

    if 22 in open_ports:
        findings.append({
            "severity": "medium",
            "title": "SSH exposé",
            "detail": "Le port 22 est ouvert et expose un service d'authentification distant."
        })
        score += 15

    if 3389 in open_ports:
        findings.append({
            "severity": "high",
            "title": "RDP exposé",
            "detail": "Le port 3389 est ouvert."
        })
        score += 25

    if smb_result and smb_result.get("executed") and smb_result.get("allowed"):
        findings.append({
            "severity": "high",
            "title": "Accès SMB invité autorisé",
            "detail": "Des partages SMB semblent accessibles sans authentification."
        })
        score += 35

    if ftp_result and ftp_result.get("executed") and ftp_result.get("allowed"):
        findings.append({
            "severity": "high",
            "title": "FTP anonyme autorisé",
            "detail": "Le service FTP accepte une connexion anonyme."
        })
        score += 35

    if ldap_result and ldap_result.get("executed") and ldap_result.get("allowed"):
        findings.append({
            "severity": "medium",
            "title": "Bind LDAP anonyme autorisé",
            "detail": "Le serveur LDAP accepte un bind anonyme."
        })
        score += 20

    if 80 in open_ports and 443 not in open_ports:
        findings.append({
            "severity": "low",
            "title": "HTTP sans HTTPS détecté",
            "detail": "Un service web en clair a été détecté sans port HTTPS associé."
        })
        score += 10

    if not findings and auth_surface.get("services"):
        findings.append({
            "severity": "info",
            "title": "Services d'authentification détectés",
            "detail": "Des services d'authentification sont ouverts mais aucun accès anonyme évident n'a été confirmé."
        })

    risk_level = "faible"
    if score >= 60:
        risk_level = "élevé"
    elif score >= 25:
        risk_level = "modéré"

    return {
        "score": min(score, 100),
        "level": risk_level,
        "findings": findings
    }


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}

    target = (data.get("target") or "").strip()
    ports = (data.get("ports") or "").strip()
    mode = normalize_mode(data.get("mode") or "Rapide")
    modules = normalize_modules(data.get("modules"))

    if not validate_target(target):
        return jsonify({"error": "Cible invalide"}), 400

    if not any(modules.values()):
        return jsonify({"error": "Aucun module sélectionné"}), 400

    nmap_result = scan_with_nmap_python(target, ports, mode) if modules.get("nmap") else None
    auth_surface = detect_auth_surface(nmap_result) if nmap_result else {"open_auth_ports": [], "services": [], "detected": {}}

    run_smb, smb_reason = should_run_module("smb", modules, nmap_result)
    run_ftp, ftp_reason = should_run_module("ftp", modules, nmap_result)
    run_ldap, ldap_reason = should_run_module("ldap", modules, nmap_result)

    smb_result = None
    ftp_result = None
    ldap_result = None

    if modules.get("smb"):
        if run_smb:
            smb_result = check_smb_anonymous(target)
            smb_result["executed"] = True
            smb_result["execution_reason"] = smb_reason
        else:
            smb_result = {
                "executed": False,
                "allowed": False,
                "shares": [],
                "message": f"Test ignoré: {smb_reason}",
                "execution_reason": smb_reason,
            }

    if modules.get("ftp"):
        if run_ftp:
            ftp_result = check_ftp_anonymous(target)
            ftp_result["executed"] = True
            ftp_result["execution_reason"] = ftp_reason
        else:
            ftp_result = {
                "executed": False,
                "allowed": False,
                "entries": [],
                "message": f"Test ignoré: {ftp_reason}",
                "execution_reason": ftp_reason,
            }

    if modules.get("ldap"):
        if run_ldap:
            ldap_result = check_ldap_anonymous(target)
            ldap_result["executed"] = True
            ldap_result["execution_reason"] = ldap_reason
        else:
            ldap_result = {
                "executed": False,
                "allowed": False,
                "naming_contexts": [],
                "message": f"Test ignoré: {ldap_reason}",
                "execution_reason": ldap_reason,
            }

    summary = build_summary(nmap_result, smb_result, ftp_result, ldap_result, modules)
    risk_assessment = build_risk_assessment(nmap_result, smb_result, ftp_result, ldap_result, auth_surface)

    response = {
        "target": target,
        "ports_input": ports,
        "mode": mode,
        "selected_modules": modules,
        "summary": summary,
        "nmap": nmap_result,
        "auth_surface": auth_surface,
        "smb": smb_result,
        "ftp": ftp_result,
        "ldap": ldap_result,
        "risk_assessment": risk_assessment,
    }

    return jsonify(response), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
