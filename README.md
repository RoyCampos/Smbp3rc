# 🧠 SMBp3rc

**SMBp3rc** es una herramienta en Bash para la enumeración y análisis automatizado de recursos compartidos SMB en una red. Permite detectar recursos accesibles, descargar archivos con extensiones sensibles y buscar posibles datos confidenciales como contraseñas, tokens y claves API.

---

## 🛠️ Requisitos

Antes de usar la herramienta, asegúrate de tener instalados los siguientes programas:

- `smbmap`
- `smbclient`
- `nmap`

Puedes instalar todos con:

```bash
sudo apt update
sudo apt install smbclient smbmap nmap -y
```

---

## 📦 Instalación

```bash
git clone https://github.com/tuusuario/smb-analyzer.git
cd smb-analyzer
chmod +x smb-analyzer.sh
```

Opcional: agrega al `$PATH` o crea un alias para usarlo desde cualquier parte.

---

## 🚀 Uso

```bash
./smb-analyzer.sh -t <IP|CIDR> [opciones]
```

### 📌 Opciones

| Opción               | Descripción                                                                 |
|----------------------|-----------------------------------------------------------------------------|
| `-t, --target`       | **(Requerido)** IP o segmento de red. Ej: `192.168.1.10` o `192.168.1.0/24` |
| `-tl, --target-list` | Archivo de texto con una lista de IPs a analizar (uno por línea).           |
| `--limit`            | Limita la cantidad de hosts a escanear (ej. `--limit 100`).                 |
| `-u, --user`         | Usuario SMB. Si se omite, se intentará acceso anónimo.                      |
| `-p, --password`     | Contraseña del usuario.                                                     |
| `-o, --output`       | Archivo de salida con resultados (por defecto en `/tmp`).                   |
| `--force-rescan`     | Fuerza un nuevo escaneo ignorando el estado anterior.                       |
| `-h, --help`         | Muestra la ayuda.                                                           |

---

## 📘 Ejemplos

### Escaneo anónimo

```bash
./smb-analyzer.sh -t 192.168.1.0/24
```

### Escaneo autenticado

```bash
./smb-analyzer.sh -t 10.0.0.55 -u administrador -p 'P@ssw0rd!'
```

### Escaneo con lista de IPs (máximo 100)

```bash
./smb-analyzer.sh -tl ips.txt --limit 100 -u user -p pass
```

### Forzar un nuevo escaneo con salida a archivo

```bash
./smb-analyzer.sh -t 192.168.100.5 --force-rescan -o resultado_host5.log
```

---

## 🔍 Qué hace el script

1. Verifica si tienes las herramientas necesarias.
2. Enumera todos los hosts del rango objetivo o desde una lista.
3. Usa `smbmap` para identificar recursos accesibles.
4. Si encuentra permisos de lectura o escritura:
   - Intenta listar archivos con extensiones sensibles.
   - Descarga archivos y busca palabras como `password`, `token`, `clave`, etc.
   - Copia archivos grandes en un directorio separado: `./huge_files/`.

---

## 📁 Estructura de salida

- `~/.config/smb_analyzer/state/`: Guarda estado de hosts ya escaneados.
- `/tmp/smb_dl.*`: Archivos descargados temporalmente.
- `./huge_files/`: Contiene archivos grandes (>100 líneas) para análisis manual.
- `*.log`: Archivo de resultados completo.

---

## ⚠️ Consideraciones

- No abuses de esta herramienta en redes que no te pertenecen o sin permiso.
- SMB puede estar bloqueado por firewalls, lo cual limitará el escaneo.
- Para entornos Windows autenticados, asegúrate de especificar correctamente el `workgroup` si es necesario.

---

## 📜 Licencia

MIT © RoyCampos