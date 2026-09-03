import pandas as pd
import os

# Rutas del proyecto
BASE = r"C:\Users\HP\Documents\auditoria-si084"

entrada = os.path.join(
    BASE,
    "20_evidencia",
    "E03_scan",
    "report-c196cf03-d50f-4b4b-9819-319efc5fd30c.csv"
)

salida = os.path.join(
    BASE,
    "40_hallazgos",
    "PT03_registro_riesgos.csv"
)

# --- EVIDENCIA TÉCNICA ---
v = pd.read_csv(entrada)

# CVSS es la columna numérica real del reporte de Greenbone
v["CVSS"] = pd.to_numeric(v["CVSS"], errors="coerce")

# Conservamos todos los hallazgos técnicos con CVSS mayor a 0
# para generar el registro de riesgos a partir de los resultados reales.
v = v[v["CVSS"] > 0]

# --- CONTEXTO DE NEGOCIO ---
ACTIVOS = {
    "si084_db": dict(
        nombre="Base de datos ERP",
        dueno="Gerencia de Finanzas",
        clasificacion="Restringida",
        expuesto=False,
        criticidad=5
    ),

    "si084_juiceshop": dict(
        nombre="Portal de clientes",
        dueno="Gerencia Comercial",
        clasificacion="Confidencial",
        expuesto=True,
        criticidad=4
    ),

    "si084_portal": dict(
        nombre="Portal corporativo",
        dueno="Gerencia Comercial",
        clasificacion="Pública",
        expuesto=True,
        criticidad=2
    ),

    "si084_dvwa": dict(
        nombre="Aplicación legada interna",
        dueno="Gerencia de Operaciones",
        clasificacion="Interna",
        expuesto=False,
        criticidad=3
    ),

    "si084_wpdb": dict(
        nombre="Base de datos del portal",
        dueno="Gerencia Comercial",
        clasificacion="Confidencial",
        expuesto=False,
        criticidad=4
    )
}


def probabilidad(cvss, expuesto):
    if cvss < 4:
        base = 1
    elif cvss < 7:
        base = 2
    elif cvss < 9:
        base = 3
    else:
        base = 4

    if expuesto:
        base += 1

    return min(5, base)


def impacto(criticidad, clasificacion):
    ajustes = {
        "Restringida": 1,
        "Confidencial": 0,
        "Interna": 0,
        "Pública": -1
    }

    valor = criticidad + ajustes.get(clasificacion, 0)

    return max(1, min(5, valor))


filas = []

for _, r in v.iterrows():

    hostname = str(r.get("Hostname", "")).strip()

    # Greenbone presenta nombres como:
    # si084_dvwa.audit_net
    # Nos quedamos solamente con si084_dvwa
    nombre_host = hostname.split(".")[0]

    activo = ACTIVOS.get(nombre_host)

    # Si el activo no está definido, se omite
    if not activo:
        continue

    cvss = float(r["CVSS"])

    p = probabilidad(
        cvss,
        activo["expuesto"]
    )

    i = impacto(
        activo["criticidad"],
        activo["clasificacion"]
    )

    riesgo = p * i

    if riesgo >= 20:
        nivel = "Crítico"
    elif riesgo >= 12:
        nivel = "Alto"
    elif riesgo >= 6:
        nivel = "Medio"
    else:
        nivel = "Bajo"

    cve = r.get("CVEs", "N/D")

    # Si Greenbone deja el CVE vacío
    if pd.isna(cve) or str(cve).strip() == "":
        cve = "N/D"

    filas.append({
        "id_riesgo": f"R-{len(filas)+1:03d}",
        "activo": activo["nombre"],
        "dueno_del_riesgo": activo["dueno"],
        "clasificacion": activo["clasificacion"],
        "amenaza": "Explotación de vulnerabilidad técnica",
        "vulnerabilidad": r.get("NVT Name", "N/D"),
        "cve": cve,
        "cvss": cvss,
        "severidad_tecnica": r.get("Severity", "N/D"),
        "probabilidad": p,
        "impacto": i,
        "riesgo_inherente": riesgo,
        "nivel": nivel
    })


# Crear DataFrame
reg = pd.DataFrame(filas)

if reg.empty:

    print(
        "No se generaron riesgos. "
        "Revisar nombres de activos y columnas del CSV."
    )

else:

    # Ordenar de mayor a menor riesgo
    reg = reg.sort_values(
        by=["riesgo_inherente", "cvss"],
        ascending=[False, False]
    )

    # Volver a numerar después del ordenamiento
    reg["id_riesgo"] = [
        f"R-{i:03d}"
        for i in range(1, len(reg) + 1)
    ]

    # Guardar CSV
    reg.to_csv(
        salida,
        index=False,
        encoding="utf-8-sig"
    )

    print("\n========================================")
    print("REGISTRO DE RIESGOS GENERADO")
    print("========================================\n")

    print(reg.to_string(index=False))

    print("\n========================================")
    print("RESUMEN")
    print("========================================")

    print(f"\nTotal de riesgos generados: {len(reg)}")

    print("\nDistribución por nivel:")
    print(reg["nivel"].value_counts().to_string())

    print("\nArchivo generado correctamente:")
    print(salida)