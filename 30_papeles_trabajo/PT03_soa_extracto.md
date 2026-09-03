\# PT03 - Declaración de Aplicabilidad (SoA)



| Control ISO/IEC 27001:2022 | Aplicable | Justificación | Estado | Riesgos relacionados |

|---|---|---|---|---|

| A.8.8 - Management of Technical Vulnerabilities | Sí | Es necesario gestionar vulnerabilidades técnicas identificadas en los activos y mantener los sistemas con soporte y actualizaciones de seguridad. | No implementado | R-002 |

| A.8.9 - Configuration Management | Sí | Se requiere mantener configuraciones seguras y controlar parámetros de red que puedan divulgar información, como TCP e ICMP Timestamps. | Parcial | R-003, R-004, R-005 |

| A.5.17 - Authentication Information | Sí | Es necesario proteger adecuadamente las credenciales y eliminar el uso de credenciales predeterminadas en los servicios de base de datos. | No implementado | R-001 |

| A.8.24 - Use of Cryptography | Sí | Se considera necesario proteger la confidencialidad de la información y las credenciales durante su almacenamiento y transmisión mediante mecanismos criptográficos apropiados. | No implementado | R-001 |

| A.7.4 - Physical Security Monitoring | No | El laboratorio se ejecuta sobre un entorno virtualizado y no contempla infraestructura física propia dentro del alcance de la evaluación. | N/A | No aplica |



\## Criterio de aplicabilidad



Los controles fueron seleccionados considerando los riesgos identificados durante el análisis técnico con Greenbone/OpenVAS y el contexto de los activos evaluados. Los controles aplicables permiten establecer medidas relacionadas con la gestión de vulnerabilidades, configuración segura, protección de credenciales y uso de mecanismos criptográficos.



El control A.7.4 - Physical Security Monitoring fue declarado como no aplicable debido a que el alcance del laboratorio corresponde a un entorno virtualizado y no incluye la evaluación de instalaciones físicas. Esta exclusión se encuentra documentada para mantener la trazabilidad de la Declaración de Aplicabilidad.

