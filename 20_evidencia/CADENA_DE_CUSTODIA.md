# Cadena de custodia de la evidencia

| ID | Archivo | SHA-256 | Fecha y hora (UTC) | Obtenido por | Metodo de obtencion | Sistema origen |
|----|---------|---------|--------------------|--------------|---------------------|----------------|
| E01-01 | compose_efectivo.yml | 8582E317EE2523F937137EA2BBD3B940973FFCEE5210F24EDA20E9AA76DA44B4 | 2026-08-26T21:10:00Z | Diego Castillo | docker compose config | Windows 11 / Docker Desktop |
| E01-02 | contenedores.json | A4C6C3D37CA61D2785A87838F0962BDC306147583E3F81D082DEEF7C150FFCD8 | 2026-08-26T21:10:00Z | Diego Castillo | docker compose ps --format json | Windows 11 / Docker Desktop |
| E01-03 | env_db.json | 12C12DDACB40D6142B00A0A48D473640010744483EE176A7B1AC4411A5112A74 | 2026-08-26T21:11:00Z | Diego Castillo | docker inspect | Windows 11 / Docker Desktop |
| E01-04 | imagenes.tsv | 136C9EB6F4A614E81136A30D08073F4AEF951A707ABF5E42972436231581CCFB | 2026-08-26T21:10:00Z | Diego Castillo | docker images --digests | Windows 11 / Docker Desktop |
| E01-05 | puertos.tsv | B1ECDFEC44144B32FEE3F406EBFE61A89832930B56FDC67B0532259E05DF31A8 | 2026-08-26T21:10:00Z | Diego Castillo | docker ps | Windows 11 / Docker Desktop |
| E01-06 | usuarios_postgres.txt | 9CC4835C0991E6B068BF4FAD929A2C5DFF6264B2E9707806DA12D75C1F9EAD73 | 2026-08-26T21:11:00Z | Diego Castillo | docker exec psql \du | Windows 11 / Docker Desktop |