\# PT03 - Casos contrastantes entre severidad técnica y riesgo de negocio



\## Caso 1: CVSS alto y riesgo de negocio menor



\*\*Activo:\*\* Aplicación legada interna  

\*\*Contenedor:\*\* si084\_dvwa  

\*\*Vulnerabilidad:\*\* Operating System (OS) End of Life (EOL) Detection  

\*\*CVSS:\*\* 10.0  

\*\*Severidad técnica:\*\* Critical  

\*\*Probabilidad:\*\* 4  

\*\*Impacto:\*\* 3  

\*\*Riesgo inherente:\*\* 12  

\*\*Nivel de riesgo:\*\* Alto  



Greenbone/OpenVAS identificó que el activo si084\_dvwa utiliza un sistema operativo que se encuentra fuera de su ciclo de soporte, asignándole una severidad técnica crítica de 10.0. Sin embargo, al incorporar el contexto del negocio, el resultado no alcanza el nivel de riesgo crítico. El activo corresponde a una aplicación legada interna, no se encuentra expuesto directamente a Internet y posee una criticidad menor que los sistemas que almacenan información restringida. Por esta razón, aunque la vulnerabilidad presenta la máxima severidad técnica, el riesgo de negocio obtenido es 12, clasificado como Alto.



Este caso demuestra que un valor CVSS elevado no determina por sí solo el nivel final del riesgo, debido a que también deben considerarse la exposición, la criticidad y el contexto del activo.



\## Caso 2: Severidad técnica baja y mayor impacto por criticidad del activo



\*\*Activo:\*\* Base de datos ERP  

\*\*Contenedor:\*\* si084\_db  

\*\*Vulnerabilidad:\*\* TCP Timestamps Information Disclosure  

\*\*CVSS:\*\* 2.6  

\*\*Severidad técnica:\*\* Low  

\*\*Probabilidad:\*\* 1  

\*\*Impacto:\*\* 5  

\*\*Riesgo inherente:\*\* 5  

\*\*Nivel de riesgo:\*\* Bajo  



Greenbone/OpenVAS detectó una vulnerabilidad de divulgación de información mediante TCP Timestamps sobre la Base de datos ERP. Técnicamente, el hallazgo posee un CVSS de 2.6 y una severidad Low. Sin embargo, el activo tiene una criticidad elevada debido a que representa una base de datos con información clasificada como Restringida, obteniendo un impacto de 5 dentro de la evaluación de negocio.



Aunque el riesgo inherente obtenido en este caso es 5 y se clasifica como Bajo debido a la baja probabilidad de explotación, el análisis evidencia que la criticidad del activo incrementa significativamente el impacto. Por ello, una vulnerabilidad de baja severidad técnica no debe descartarse automáticamente sin analizar previamente el valor del activo para la organización.



\## Conclusión de los casos contrastantes



Los resultados evidencian que la severidad técnica de una vulnerabilidad y el riesgo de negocio representan conceptos diferentes. El CVSS permite valorar características técnicas de una vulnerabilidad, mientras que el riesgo requiere incorporar factores relacionados con el activo, como su criticidad, clasificación de la información y exposición. Por este motivo, los hallazgos obtenidos mediante Greenbone/OpenVAS fueron contextualizados antes de establecer su nivel de riesgo.

