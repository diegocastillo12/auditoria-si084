# Conclusiones

1. Considero que la reproducibilidad del entorno auditado fue clave en esta practica: al contar con un archivo de composicion (docker-compose.yml) versionado en Git, cualquier persona puede reconstruir exactamente el mismo entorno y llegar al mismo resultado que yo obtuve. Sin esa reproducibilidad, mis hallazgos dependerian unicamente de mi palabra como auditor, lo cual les resta solidez.

2. Entendi que la cadena de custodia no es un simple tramite burocratico, sino el mecanismo real que convierte un archivo cualquiera en evidencia defendible. Al calcular el hash SHA-256 de cada artefacto y registrar quien, como y cuando lo obtuve, cualquier alteracion posterior queda expuesta de inmediato, algo que pude comprobar cuando modifique puertos.tsv a proposito y su hash cambio completamente.

3. Tambien concluyo que la linea base que capture al inicio del laboratorio es el unico punto de referencia confiable para poder demostrar, mas adelante, que cambio en el sistema durante la auditoria y en que momento ocurrio ese cambio. Sin esta fotografia inicial del entorno, seria imposible distinguir una configuracion original de una modificada durante el proceso.
