#!/bin/bash

# Salir immediately si un comando falla o si se usa una variable no definida.
set -euo pipefail

# --- Constantes y Configuración Global ---
readonly SCRIPT_NAME=$(basename "$0")
readonly STATE_DIR="${HOME}/.config/smb_analyzer/state"
readonly INTERESTING_EXTS=(
  # Documentos y texto
  "txt" "log" "csv" "pdf" "doc" "docx" "odt" "rtf" "tex"

  # Hojas de cálculo y presentaciones
  "xls" "xlsx" "ods" "csv" "tsv"
  "ppt" "pptx" "odp"

  # Archivos de configuración
  "conf" "config" "cfg" "ini" "yml" "yaml" "json" "xml" "toml" "env"

  # Archivos de código fuente y scripts
  "sh" "bash" "zsh" "bat" "cmd" "ps1"
  "py" "rb" "php" "js" "ts" "java" "c" "cpp" "cs" "go" "swift"
  "jsp" "aspx" "asp" "html" "htm"

  # Claves y certificados
  "pem" "key" "cer" "crt" "pfx" "p12"

  # Backups y archivos sensibles
  "bak" "backup" "old" "orig" "tmp" "swp" "swo"
  "sql" "sqlite" "db" "db3" "mdb" "accdb"

  # Credenciales y acceso remoto
  "rdp" "kdb" "kdbx" "vnc" "ovpn" "pcf" "cred"

  # Variables de entorno
  ".env" ".bashrc" ".zshrc" ".profile" ".bash_profile"

  # Archivos comprimidos (pueden contener configuraciones o bases de datos)
  "zip" "rar" "7z" "tar" "gz" "bz2"

  # Licencias y legal
  "license" "lic" "eula" "terms"

  # Notas o tareas internas
  "todo" "note" "notes" "ideas" "plan" "roadmap"

  # Archivos ocultos o Unix comunes
  ".bash_history" ".mysql_history" ".viminfo"
  
  # Archivos que suelen contener configuración de servicios
  "docker-compose.yml" "dockerfile" "vagrantfile" "Procfile" "Makefile"
  "package.json" "composer.json" "requirements.txt" "Gemfile"
  
  # Carpetas o rutas clave (si haces análisis más avanzado de nombres de ruta)
  "secrets" "vault" "config" "private" "credentials" "keys"
)

readonly SENSITIVE_KEYWORDS="(?i)\\b(pass(word)?|clave|contraseña|secret|token|apikey|api_key|auth|authentication|credenciales?|credential|session|cookie|bearer|jwt|private[_-]?key|public[_-]?key|ssh[_-]?key|rsa|dsa|aes|encryption|license|keycode|serial|pin|admin|usuario|username|user|login|access[_-]?key|db[_-]?pass|database[_-]?password|smtp[_-]?pass|mail[_-]?user|ftp[_-]?password|aws[_-]?(secret|access)[_-]?key|gcp[_-]?credentials?|azure[_-]?key|ntlm|hash|md5|sha256|hmac|oauth|saml|sso|vault|secreto)\\b"

# Colores
readonly YELLOW='\033[1;33m'
readonly RED='\033[1;31m'
readonly GREEN='\033[1;32m'
readonly BLUE='\033[1;34m'
readonly NC='\033[0m'

# --- Funciones de la Herramienta ---

show_help() {
    echo "Uso: ${SCRIPT_NAME} -t <TARGET> [-tl <IP_LIST>] [-u <USER>] [-p <PASS>] [-o <OUTPUT_FILE>] [--force-rescan] [--limit <N>]"
    echo ""
    echo "Herramienta para analizar recursos compartidos SMB, buscar archivos de interés y"
    echo "encontrar datos sensibles. Puede escanear un solo host o un segmento de red."
    echo ""
    echo "Opciones:"
    echo "  -t, --target <IP|CIDR>  IP o segmento de red (ej. 192.168.1.10 o 192.168.1.0/24). (Requerido)"
    echo "  -tl, --target-list <FILE>     Archivo con lista de IPs (una por línea)."
    echo "  -u, --user <USERNAME>   Nombre de usuario para la autenticación (default: anónimo, texto vacío)."
    echo "  -p, --password <PASSWD> Contraseña para la autenticación (default: vacía)."
    echo "  -o, --output <FILE>     Archivo donde se guardarán los resultados. (Default: /tmp/smb_analysis_TARGET_TIMESTAMP.log)"
    echo "      --force-rescan      Forzar un escaneo desde cero, ignorando el historial."
    echo "      --limit <N>      Limitar el número de hosts a escanear (default: sin límite)."
    echo "  -h, --help              Mostrar este mensaje de ayuda."
    exit 0
}

check_deps() {
    declare -A deps_map=([smbmap]="smbmap" [smbclient]="smbclient" [nmap]="nmap")
    local missing_packages=()
    echo -e "${BLUE}[*] Verificando dependencias...${NC}"
    for cmd in "${!deps_map[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_packages+=("${deps_map[$cmd]}")
        fi
    done
    if [ ${#missing_packages[@]} -gt 0 ]; then
        echo -e "${YELLOW}[!] Dependencias requeridas no encontradas:${NC} ${missing_packages[*]}"
        read -p "    ¿Deseas intentar instalarlas ahora? (y/n): " -n 1 -r; echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${BLUE}[*] Intentando instalar paquetes...${NC}"
            sudo apt-get update && sudo apt-get install -y "${missing_packages[@]}"
        else
            echo -e "${RED}[!] Instalación cancelada. No se puede continuar.${NC}"; exit 1
        fi
    else
        echo -e "${GREEN}[+] Todas las dependencias están instaladas.${NC}"
    fi
}

scan_host() {
    local host="$1"
    local user="$2"
    local pass="$3"
    local results_file="$4"

    echo -e "\n${BLUE}══════════════════════════════════════════════${NC}"
    echo -e "${BLUE}>> ANALIZANDO HOST: ${YELLOW}$host${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════${NC}"
    echo -e "\n================ HOST: $host ================" >> "$results_file"

    local tmp_dl_dir
    tmp_dl_dir=$(mktemp -d "/tmp/smb_dl.${host}.XXXXXX")
    local smb_output_file
    smb_output_file=$(mktemp "/tmp/smb_output.XXXXXX")
    trap 'rm -rf "$tmp_dl_dir" "$smb_output_file"' RETURN

    echo -e "${BLUE}→ Ejecutando smbmap...${NC}"
    smbmap --timeout 60 -u "$user" -p "$pass" -d "workgroup" -H "$host" > "$smb_output_file" 2>&1 || true

    mapfile -t all_shares < <(grep -E 'READ|WRITE|NO ACCESS' "$smb_output_file")

    if [ ${#all_shares[@]} -eq 0 ]; then
        echo -e "${YELLOW}✗ No se pudieron listar recursos compartidos en $host.${NC}"
        echo "[INFO] No se pudieron listar recursos compartidos." >> "$results_file"
        return
    fi

    local accessible_shares=()
    local info_only_shares=()
    for share_line in "${all_shares[@]}"; do
        [[ -z "$share_line" ]] && continue
        local permissions
        permissions=$(echo "$share_line" | awk '{print $2}')
        if [[ "$permissions" == *"READ"* || "$permissions" == *"WRITE"* ]]; then
            accessible_shares+=("$share_line")
        else
            info_only_shares+=("$share_line")
        fi
    done

    if [ ${#accessible_shares[@]} -gt 0 ]; then
        echo -e "${GREEN}✓ ${#accessible_shares[@]} recurso(s) con permisos de lectura/escritura encontrados.${NC}"
        for share_line in "${accessible_shares[@]}"; do
            local share_name permissions
            share_name=$(echo "$share_line" | awk '{print $1}')
            permissions=$(echo "$share_line" | awk '{print $2}')

            echo -e "\n${GREEN}★ Analizando recurso: ${YELLOW}$share_name${NC} ${BLUE}| Permisos: $permissions${NC}"
            echo -e "\n>>> [ACCESIBLE] Compartido: $share_name | Permiso: $permissions" >> "$results_file"

            if [[ "$permissions" == *"WRITE"* ]]; then
                echo -e "${RED}✗ El recurso '${share_name}' tiene permisos de ESCRITURA.${NC}"
                echo "[ALERTA] Permisos de escritura encontrados en '$share_name'." >> "$results_file"
            fi

            if [[ "$permissions" == *"READ"* ]]; then
                echo -e "${BLUE}→ Buscando archivos interesantes en '${share_name}'...${NC}"
                mapfile -t files_to_download < <(
                    smbclient "//$host/$share_name" -W "workgroup" -U "$user%$pass" -c "recurse ON; ls" 2>/dev/null \
                    | awk '{for (i=NF; i>0; i--) if ($i ~ /\.[a-zA-Z0-9]+$/) { print $i; break }}' \
                    | grep -iE "\.($(IFS='|'; echo "${INTERESTING_EXTS[*]}"))$" | sort -u || true
                )

                if [ ${#files_to_download[@]} -gt 0 ]; then
                    echo -e "${GREEN}✓ Se encontraron ${#files_to_download[@]} archivo(s) relevante(s). Descargando...${NC}"
                    local smb_cmds="lcd $tmp_dl_dir; prompt OFF; recurse ON;"
                    for file_path in "${files_to_download[@]}"; do
                        smb_cmds+="mget \"$file_path\";"
                    done
                    smbclient "//$host/$share_name" -W "workgroup" -U "$user%$pass" -c "$smb_cmds" &>/dev/null

                    find "$tmp_dl_dir" -type f -print0 | while IFS= read -r -d '' local_file; do
                        local filename
                        filename=$(basename "$local_file")
                        if grep -iaE "$SENSITIVE_KEYWORDS" "$local_file" > /dev/null 2>&1; then
                            echo -e "${RED}‼ Datos sensibles encontrados en: $share_name\\$filename${NC}"
                            echo "[SENSIBLE] Archivo: $share_name\\$filename" >> "$results_file"
                            grep -inaE "$SENSITIVE_KEYWORDS" "$local_file" | while IFS= read -r match_line; do
                                echo "    → $match_line" | tee -a "$results_file"
                            done
                        else
                            local line_count
                            line_count=$(wc -l < "$local_file")
                            if [ "$line_count" -le 100 ]; then
                                echo -e "${BLUE}• Mostrando contenido completo de $filename ($line_count líneas)${NC}"
                                echo "    ---" | tee -a "$results_file"
                                cat "$local_file" | tee -a "$results_file"
                                echo "    ---" | tee -a "$results_file"
                            else
                                mkdir -p "$(pwd)/huge_files"
                                cp "$local_file" "$(pwd)/huge_files/$filename"
                                echo -e "${YELLOW}⚠ Archivo grande ($line_count líneas) copiado a ./huge_files/$filename${NC}"
                                echo "    [INFO] Archivo grande copiado: $filename" >> "$results_file"
                            fi
                        fi
                    done
                else
                    echo -e "${YELLOW}• No se encontraron archivos con extensiones de interés en '$share_name'.${NC}"
                    echo "    [INFO] No se encontraron archivos de interés en '$share_name'." >> "$results_file"
                fi
            fi
        done
    else
        echo -e "${YELLOW}• No hay recursos con permisos R/W. Mostrando recursos visibles:${NC}"
        echo -e "\n[INFO] No se encontraron recursos con permisos R/W. Listado de todos los recursos visibles:" >> "$results_file"
        for share_line in "${info_only_shares[@]}"; do
            echo -e "    → $share_line" | tee -a "$results_file"
        done
    fi
}

# --- Parseo de Argumentos y Lógica Principal ---

TARGET=""
TARGET_LIST=""
USER="${SMB_USER:-}"
PASS="${SMB_PASS:-}"
OUTPUT_FILE=""
FORCE_RESCAN=false
LIMIT=0

while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        -t|--target) TARGET="$2"; shift; shift;;
        -tl|--target-list) TARGET_LIST="$2"; shift; shift;;
        -u|--user) USER="$2"; shift; shift;;
        -p|--password) PASS="$2"; shift; shift;;
        -o|--output) OUTPUT_FILE="$2"; shift; shift;;
        --force-rescan) FORCE_RESCAN=true; shift;;
        --limit) LIMIT="$2"; shift; shift;;
        -h|--help) show_help;;
        *) echo "Opción desconocida: $1"; show_help;;
    esac
done

if [[ -z "$TARGET" && -z "$TARGET_LIST" ]]; then
    echo -e "${RED}[!] Error: El argumento --target es requerido.${NC}"; show_help
    echo -e "${RED}[!] Debes especificar -t o -tl.${NC}"; show_help
fi

# --- CAMBIO: Ahora el usuario por defecto es un texto vacío ---
USER="${USER:-}"
PASS="${PASS:-}"

check_deps
mkdir -p "$STATE_DIR"

if [[ -n "$TARGET_LIST" ]]; then
    mapfile -t all_hosts < "$TARGET_LIST"
    TARGET_CLEAN=$(basename "$TARGET_LIST" | tr '.' '_' | tr '/' '_')
else
    mapfile -t all_hosts < <(nmap -sL -n "$TARGET" | awk '/Nmap scan report for/{print $NF}')
    TARGET_CLEAN=$(echo "$TARGET" | tr '/.' '_')
fi


STATE_FILE="${STATE_DIR}/${TARGET_CLEAN}.state"
if [[ -z "$OUTPUT_FILE" ]]; then
    OUTPUT_FILE="/tmp/smb_analysis_${TARGET_CLEAN}_$(date +%s).log"
fi

if [[ "$FORCE_RESCAN" = true ]] && [[ -f "$STATE_FILE" ]]; then
    echo -e "${YELLOW}[*] Forzando re-escaneo. Se ha eliminado el historial anterior.${NC}"; rm "$STATE_FILE"
fi
touch "$STATE_FILE"

echo -e "${YELLOW}[+] Análisis iniciado. Resultados en: ${NC}${OUTPUT_FILE}"
echo "Análisis de SMB para $TARGET - $(date)" > "$OUTPUT_FILE"

#mapfile -t all_hosts < <(nmap -sL -n "$TARGET" | awk '/Nmap scan report for/{print $NF}')
#echo -e "${YELLOW}[+] Total de hosts a escanear: ${#all_hosts[@]}${NC}"

mapfile -t completed_hosts < "$STATE_FILE"
echo -e "${YELLOW}[+] Hosts ya completados: ${#completed_hosts[@]}${NC}"

count=0
for host in "${all_hosts[@]}"; do
    if grep -qxF "$host" "$STATE_FILE"; then
        echo -e "${BLUE}[-] Omitiendo host ya analizado: $host${NC}"; continue
    fi
    scan_host "$host" "$USER" "$PASS" "$OUTPUT_FILE"
    echo "$host" >> "$STATE_FILE"
    count=$((count + 1))
    if [[ "$LIMIT" -gt 0 && "$count" -ge "$LIMIT" ]]; then
        echo -e "${YELLOW}[+] Límite de $LIMIT alcanzado.${NC}"
        break
    fi
done

echo -e "\n${GREEN}[++] Análisis finalizado completamente.${NC}"
echo -e "${BLUE}----------------------------------------------------${NC}"
echo -e "${BLUE}--- Contenido en el log: ${YELLOW}$OUTPUT_FILE${BLUE} ---${NC}"
#echo -e "${BLUE}----------------------------------------------------${NC}"
#cat "$OUTPUT_FILE"
#echo -e "${BLUE}----------------------------------------------------${NC}"