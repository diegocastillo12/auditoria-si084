import pandas as pd
import json
import re
import glob

filas = []

# =========================================================
# LYNIS
# =========================================================
for l in open("../20_evidencia/E04_config/lynis-report.dat", encoding="utf-8", errors="ignore"):
    if l.startswith("warning[]=") or l.startswith("suggestion[]="):
        tipo = "warning" if l.startswith("warning") else "suggestion"

        filas.append({
            "herramienta": "Lynis",
            "severidad": "Alta" if tipo == "warning" else "Media",
            "hallazgo": l.split("=", 1)[1].strip()[:200]
        })


# =========================================================
# DOCKER BENCH
# =========================================================
for l in open("../20_evidencia/E04_config/docker-bench.log", encoding="utf-8", errors="ignore"):

    # Quitar codigos ANSI de colores
    limpio = re.sub(r"\x1b\[[0-9;]*m", "", l)

    if "[WARN]" in limpio:
        filas.append({
            "herramienta": "Docker Bench",
            "severidad": "Alta",
            "hallazgo": limpio.replace("[WARN]", "").strip()[:200]
        })


# =========================================================
# TRIVY
# =========================================================
for f in glob.glob("../20_evidencia/E04_config/trivy/*.json") + \
         glob.glob("../20_evidencia/E04_config/trivy_*.json"):

    try:
        with open(f, encoding="utf-8", errors="ignore") as archivo:
            d = json.load(archivo)

        for res in d.get("Results", []):
            for v in res.get("Vulnerabilities", []) or []:

                filas.append({
                    "herramienta": "Trivy",
                    "severidad": v.get("Severity", "Desconocida").capitalize(),
                    "hallazgo": (
                        f'{v.get("VulnerabilityID", "")} '
                        f'en {v.get("PkgName", "")} '
                        f'{v.get("InstalledVersion", "")}'
                    ).strip()
                })

    except Exception:
        pass


# =========================================================
# DATAFRAME
# =========================================================
m = pd.DataFrame(filas)

if m.empty:
    print("No se encontraron hallazgos.")
    exit()


# =========================================================
# MAPEO ISO/IEC 27001 + COBIT 2019
# =========================================================
MAPEO = [

    # Accesos privilegiados / contenedores
    (
        r"root|privileg|capab|user for the container|apparmor|selinux|securityoptions|security options",
        "A.8.2 Privileged access rights",
        "DSS05.04"
    ),

    # Autenticacion
    (
        r"password|credential|secret|auth|authentication",
        "A.5.17 Authentication information",
        "DSS05.04"
    ),

    # Vulnerabilidades y paquetes
    (
        r"CVE-|vulnerab|outdated|version|apt-get update|package|packages|PKGS-|debsums",
        "A.8.8 Management of technical vulnerabilities",
        "DSS05.07"
    ),

    # Logs y auditoria
    (
        r"log|audit|journal|accounting|sysstat|ACCT-",
        "A.8.15 Logging",
        "DSS01.03"
    ),

    # Criptografia
    (
        r"tls|ssl|cipher|encrypt|certificate|content trust|signed image",
        "A.8.24 Use of cryptography",
        "DSS05.03"
    ),

    # Red
    (
        r"firewall|port|network|expose|protocol|dccp|sctp|rds|tipc|hosts|fqdn|userland proxy|NETW-|socket",
        "A.8.20 Networks security",
        "DSS05.02"
    ),

    # Gestion de configuracion
    (
        r"config|default|hardening|sysctl|kernel|KRNL-|ownership|partition|FILE-|mount|read-only|read only",
        "A.8.9 Configuration management",
        "BAI10.02"
    ),

    # Backup
    (
        r"backup|restore|recovery",
        "A.8.13 Information backup",
        "DSS04.07"
    ),

    # Capacidad: memoria, CPU, PID
    (
        r"memory|CPU|cpu|PIDs|pid|cgroup|resource restriction|resource limit|limit not set",
        "A.8.6 Capacity management",
        "BAI04.01"
    ),

    # Monitoreo y healthcheck
    (
        r"healthcheck|health check|health check not set|No Healthcheck found",
        "A.8.16 Monitoring activities",
        "DSS01.03"
    ),

    # Integridad de archivos
    (
        r"file integrity|integrity tool|FINT-",
        "A.8.9 Configuration management",
        "BAI10.02"
    ),

    # Automatizacion
    (
        r"automation|TOOL-",
        "A.8.9 Configuration management",
        "BAI10.02"
    ),

    # Disponibilidad y particiones
    (
        r"/home|/tmp|/var|full filesystem|full partition|separate partition",
        "A.8.6 Capacity management",
        "BAI04.01"
    ),

    # Propiedad de archivos / Docker
    (
        r"wrong ownership|docker.sock|ownership for",
        "A.8.9 Configuration management",
        "BAI10.02"
    ),

    # Restricciones de ejecucion
    (
        r"seccomp|no-new-privileges|no new privileges",
        "A.8.2 Privileged access rights",
        "DSS05.04"
    ),

    # Reinicio / disponibilidad
    (
        r"restart policy|restart policies",
        "A.8.14 Redundancy of information processing facilities",
        "DSS04.05"
    )
]


# =========================================================
# FUNCION DE CLASIFICACION
# =========================================================
def clasifica(texto):

    texto = str(texto)

    for patron, iso, cobit in MAPEO:

        if re.search(patron, texto, re.IGNORECASE):
            return pd.Series([iso, cobit])

    return pd.Series(["Sin clasificar", "Sin clasificar"])


m[["control_iso27001", "objetivo_cobit"]] = m["hallazgo"].apply(clasifica)


# =========================================================
# GUARDAR MATRIZ
# =========================================================
salida = "../40_hallazgos/PT04_matriz_control.csv"

m.to_csv(
    salida,
    index=False,
    encoding="utf-8-sig"
)


# =========================================================
# RESULTADOS
# =========================================================
print()
print("==============================================")
print("HALLAZGOS POR HERRAMIENTA")
print("==============================================")

print(
    m.groupby(
        ["herramienta", "severidad"]
    ).size().to_string()
)


print()
print("==============================================")
print("HALLAZGOS POR CONTROL ISO")
print("==============================================")

print(
    m["control_iso27001"]
    .value_counts()
    .to_string()
)


# =========================================================
# VALIDACION DE SIN CLASIFICAR
# =========================================================
total = len(m)

sin_clasificar = (
    m["control_iso27001"] == "Sin clasificar"
).sum()

porcentaje = (
    sin_clasificar / total * 100
) if total > 0 else 0


print()
print("==============================================")
print("VALIDACION FINAL")
print("==============================================")

print(f"Total de hallazgos: {total}")
print(f"Sin clasificar: {sin_clasificar} ({porcentaje:.2f}%)")


if porcentaje < 20:
    print("RESULTADO: CUMPLE - Menos del 20% sin clasificar")
else:
    print("RESULTADO: NO CUMPLE - Se requiere clasificacion adicional")


print()
print(f"Matriz generada en: {salida}")