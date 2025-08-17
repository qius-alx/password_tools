#!/usr/bin/env python3
"""
Password Tool - Herramienta de Ciberseguridad para Contraseñas
Autor: Tu nombre
Descripción: Herramienta completa para análisis, generación y gestión de contraseñas
"""

import os
import sys
import json
import hashlib
import secrets
import string
import getpass
import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class Colors:
    """Códigos de colores ANSI para terminal"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class PasswordTool:
    def __init__(self):
        self.passwords_file = "passwords.enc"
        self.salt_file = "salt.key"
        
    def show_banner(self):
        """Muestra el banner principal del programa con diseño profesional"""
        banner = (
            f"{Colors.CYAN}{Colors.BOLD}"
            "    ____                                     _   _______            _ \n"
            "   |  _ \\ __ _ ___ ___ __      _____  _ __ __| | |__   __|___   ___ | |\n"
            "   | |_) / _` / __/ __\\ \\ /\\ / / _ \\| '__/ _` |    | |/ _ \\ \\ / _ \\| |\n"
            "   |  __/ (_| \\__ \\__ \\\\ V  V / (_) | | | (_| |    | | (_) | | (_) | |\n"
            "   |_|   \\__,_|___/___/ \\_/\\_/ \\___/|_|  \\__,_|    |_|\\___/  |_\\___/|_|\n"
            "                                                                      \n"
            f"{Colors.PURPLE}"
            "┌──────────────────────────────────────────────────────────────────────┐\n"
            "│                🔐 PASSWORD SECURITY TOOLKIT v2.0 🔐                  │\n"
            "│                     Herramienta de Ciberseguridad                    │\n"
            "│                                                                      │\n"
            "│  GitHub: qius-alx/password-tools                                     │\n"
            "│  TikTok: SyntaxLab                                                   │\n"
            "│  Autor: qius-alx                                                     │\n"
            "│  Para análisis, generación y gestión segura de contraseñas           │\n"
            "└──────────────────────────────────────────────────────────────────────┘\n"
            f"{Colors.BOLD}════════════════════[ M E N Ú   P R I N C I P A L ]═════════════════════{Colors.END}\n"
        )
        
        print(banner)
        
        # Menú con colores
        options = [
            ("1", "🔍 Analizar contraseña", "Evalúa la fortaleza de tu contraseña"),
            ("2", "🎲 Generar contraseña segura", "Crea contraseñas aleatorias robustas"),
            ("3", "🔐 Guardar/Gestionar contraseñas", "Gestor cifrado de contraseñas"),
            ("4", "🌐 Verificar si está filtrada (HIBP)", "Consulta base de datos de brechas"),
            ("5", "📝 Convertir frase → contraseña", "Transforma frases en contraseñas seguras"),
            ("0", "🚪 Salir", "Terminar programa")
        ]
        
        print(f"{Colors.WHITE}{Colors.BOLD}OPCIONES DISPONIBLES:{Colors.END}")
        print()
        for num, title, desc in options:
            print(f"  {Colors.YELLOW}[{num}]{Colors.END} {Colors.GREEN}{title}{Colors.END}")
            print(f"      {Colors.CYAN}{desc}{Colors.END}")
            print()
        
        print(f"{Colors.PURPLE}{'═' * 72}{Colors.END}")
        print(f"{Colors.RED}{Colors.BOLD}⚠️  AVISO:{Colors.END} {Colors.YELLOW}Usa esta herramienta de forma ética y responsable{Colors.END}")
        print(f"{Colors.BLUE}💡 Tip: Las contraseñas no se almacenan sin cifrado{Colors.END}\n")
    
    def analyze_password(self, password):
        """Analiza la fortaleza de una contraseña"""
        score = 0
        feedback = []
        
        # Longitud
        if len(password) >= 12:
            score += 2
            feedback.append("✅ Longitud adecuada (12+ caracteres)")
        elif len(password) >= 8:
            score += 1
            feedback.append("⚠️  Longitud aceptable (8+ caracteres)")
        else:
            feedback.append("❌ Muy corta (menos de 8 caracteres)")
        
        # Mayúsculas
        if any(c.isupper() for c in password):
            score += 1
            feedback.append("✅ Contiene mayúsculas")
        else:
            feedback.append("❌ No contiene mayúsculas")
        
        # Minúsculas
        if any(c.islower() for c in password):
            score += 1
            feedback.append("✅ Contiene minúsculas")
        else:
            feedback.append("❌ No contiene minúsculas")
        
        # Números
        if any(c.isdigit() for c in password):
            score += 1
            feedback.append("✅ Contiene números")
        else:
            feedback.append("❌ No contiene números")
        
        # Símbolos especiales
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        if any(c in special_chars for c in password):
            score += 1
            feedback.append("✅ Contiene símbolos especiales")
        else:
            feedback.append("❌ No contiene símbolos especiales")
        
        # Patrones comunes (penalización)
        common_patterns = ["123", "abc", "password", "qwerty", "admin"]
        for pattern in common_patterns:
            if pattern.lower() in password.lower():
                score -= 1
                feedback.append(f"❌ Contiene patrón común: {pattern}")
        
        # Determinar nivel de seguridad
        if score >= 5:
            level = "🟢 FUERTE"
        elif score >= 3:
            level = "🟡 MEDIA"
        else:
            level = "🔴 DÉBIL"
        
        return {
            'score': score,
            'level': level,
            'feedback': feedback
        }
    
    def generate_password(self, length=16, include_symbols=True):
        """Genera una contraseña segura aleatoria"""
        characters = string.ascii_letters + string.digits
        if include_symbols:
            characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Asegurar que tenga al menos un carácter de cada tipo
        password = [
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.digits)
        ]
        
        if include_symbols:
            password.append(secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?"))
        
        # Llenar el resto de la longitud
        for _ in range(length - len(password)):
            password.append(secrets.choice(characters))
        
        # Mezclar la contraseña
        secrets.SystemRandom().shuffle(password)
        return ''.join(password)
    
    def derive_key(self, password, salt):
        """Deriva una clave de cifrado a partir de una contraseña"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def get_or_create_salt(self):
        """Obtiene o crea un salt para el cifrado"""
        if os.path.exists(self.salt_file):
            with open(self.salt_file, 'rb') as f:
                return f.read()
        else:
            salt = os.urandom(16)
            with open(self.salt_file, 'wb') as f:
                f.write(salt)
            return salt
    
    def encrypt_data(self, data, master_password):
        """Cifra los datos usando la contraseña maestra"""
        salt = self.get_or_create_salt()
        key = self.derive_key(master_password, salt)
        f = Fernet(key)
        return f.encrypt(data.encode())
    
    def decrypt_data(self, encrypted_data, master_password):
        """Descifra los datos usando la contraseña maestra"""
        salt = self.get_or_create_salt()
        key = self.derive_key(master_password, salt)
        f = Fernet(key)
        try:
            return f.decrypt(encrypted_data).decode()
        except:
            return None
    
    def load_passwords(self, master_password):
        """Carga las contraseñas guardadas"""
        if not os.path.exists(self.passwords_file):
            return {}
        
        try:
            with open(self.passwords_file, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = self.decrypt_data(encrypted_data, master_password)
            if decrypted_data is None:
                print("❌ Contraseña maestra incorrecta")
                return None
            
            return json.loads(decrypted_data)
        except Exception as e:
            print(f"❌ Error al cargar contraseñas: {e}")
            return None
    
    def save_passwords(self, passwords, master_password):
        """Guarda las contraseñas cifradas"""
        try:
            data = json.dumps(passwords, indent=2)
            encrypted_data = self.encrypt_data(data, master_password)
            
            with open(self.passwords_file, 'wb') as f:
                f.write(encrypted_data)
            
            print("✅ Contraseñas guardadas correctamente")
            return True
        except Exception as e:
            print(f"❌ Error al guardar contraseñas: {e}")
            return False
    
    def manage_passwords(self):
        """Gestiona el almacén de contraseñas"""
        print(f"\n{Colors.PURPLE}🔐 GESTOR DE CONTRASEÑAS{Colors.END}")
        print(f"{Colors.PURPLE}{'-' * 30}{Colors.END}")
        
        master_password = getpass.getpass("Ingresa tu contraseña maestra: ")
        passwords = self.load_passwords(master_password)
        
        if passwords is None:
            return
        
        while True:
            print(f"\n{Colors.CYAN}[1]{Colors.END} Ver contraseñas")
            print(f"{Colors.CYAN}[2]{Colors.END} Agregar contraseña")
            print(f"{Colors.CYAN}[3]{Colors.END} Eliminar contraseña")
            print(f"{Colors.CYAN}[0]{Colors.END} Volver al menú principal")
            
            choice = input(f"\n{Colors.BOLD}Selecciona una opción: {Colors.END}").strip()
            
            if choice == '1':
                if not passwords:
                    print(f"{Colors.YELLOW}No hay contraseñas guardadas.{Colors.END}")
                else:
                    print(f"\n{Colors.GREEN}📋 CONTRASEÑAS GUARDADAS:{Colors.END}")
                    for service, data in passwords.items():
                        print(f"{Colors.CYAN}🔸 {service}:{Colors.END} {data['username']} | {Colors.GREEN}{data['password']}{Colors.END}")
            
            elif choice == '2':
                service = input("Nombre del servicio: ").strip()
                username = input("Usuario/Email: ").strip()
                password = input("Contraseña (deja vacío para generar): ").strip()
                
                if not password:
                    length = input("Longitud de contraseña (16): ").strip() or "16"
                    try:
                        length = int(length)
                        password = self.generate_password(length)
                        print(f"{Colors.GREEN}✅ Contraseña generada: {Colors.CYAN}{password}{Colors.END}")
                    except ValueError:
                        print(f"{Colors.RED}❌ Longitud inválida{Colors.END}")
                        continue
                
                passwords[service] = {
                    'username': username,
                    'password': password
                }
                
                if self.save_passwords(passwords, master_password):
                    print(f"{Colors.GREEN}✅ Contraseña para {service} guardada{Colors.END}")
            
            elif choice == '3':
                if not passwords:
                    print(f"{Colors.YELLOW}No hay contraseñas para eliminar.{Colors.END}")
                else:
                    print(f"\n{Colors.CYAN}Servicios disponibles:{Colors.END}")
                    for service in passwords.keys():
                        print(f"- {service}")
                    
                    service = input("¿Qué servicio eliminar? ").strip()
                    if service in passwords:
                        del passwords[service]
                        if self.save_passwords(passwords, master_password):
                            print(f"{Colors.GREEN}✅ Contraseña de {service} eliminada{Colors.END}")
                    else:
                        print(f"{Colors.RED}❌ Servicio no encontrado{Colors.END}")
            
            elif choice == '0':
                break
            else:
                print(f"{Colors.RED}❌ Opción inválida{Colors.END}")
    
    def check_hibp(self, password):
        """Verifica si una contraseña aparece en filtraciones usando Have I Been Pwned"""
        print(f"\n{Colors.CYAN}🔍 VERIFICANDO EN HAVE I BEEN PWNED...{Colors.END}")
        
        try:
            # Crear hash SHA-1 de la contraseña
            sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            
            # Los primeros 5 caracteres del hash
            prefix = sha1[:5]
            suffix = sha1[5:]
            
            # Consultar la API de HIBP
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            headers = {'User-Agent': 'Password-Tool-Python'}
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                # Buscar el sufijo en la respuesta
                hashes = response.text.split('\n')
                for hash_line in hashes:
                    if ':' in hash_line:
                        hash_suffix, count = hash_line.split(':')
                        if hash_suffix == suffix:
                            print(f"{Colors.RED}{Colors.BOLD}❌ ¡CONTRASEÑA COMPROMETIDA!{Colors.END}")
                            print(f"   {Colors.YELLOW}Encontrada {Colors.RED}{count.strip()}{Colors.YELLOW} veces en filtraciones{Colors.END}")
                            return True
                
                print(f"{Colors.GREEN}✅ Contraseña no encontrada en filtraciones conocidas{Colors.END}")
                return False
            
            else:
                print(f"{Colors.RED}❌ Error en la consulta: {response.status_code}{Colors.END}")
                return None
        
        except requests.exceptions.RequestException as e:
            print(f"{Colors.RED}❌ Error de conexión: {e}{Colors.END}")
            print(f"{Colors.YELLOW}Verifica tu conexión a internet{Colors.END}")
            return None
        except Exception as e:
            print(f"{Colors.RED}❌ Error inesperado: {e}{Colors.END}")
            return None
    
    def phrase_to_password(self, phrase):
        """Convierte una frase en una contraseña segura"""
        # Diccionario de reemplazos
        replacements = {
            'a': '@', 'A': '@',
            'e': '3', 'E': '3',
            'i': '!', 'I': '!',
            'o': '0', 'O': '0',
            's': '$', 'S': '$',
            't': '7', 'T': '7',
            'l': '1', 'L': '1',
            ' ': '_'
        }
        
        password = ""
        for char in phrase:
            password += replacements.get(char, char)
        
        # Agregar algunos números y símbolos al final
        password += str(secrets.randbelow(100)).zfill(2)
        password += secrets.choice("!@#$%&*")
        
        return password
    
    def run_option_1(self):
        """Ejecuta la opción 1: Analizar contraseña"""
        print(f"\n{Colors.CYAN}🔍 ANÁLISIS DE CONTRASEÑA{Colors.END}")
        print(f"{Colors.PURPLE}{'-' * 30}{Colors.END}")
        
        password = getpass.getpass("Ingresa la contraseña a analizar: ")
        if not password:
            print(f"{Colors.RED}❌ No se ingresó contraseña{Colors.END}")
            return
        
        result = self.analyze_password(password)
        
        print(f"\n{Colors.BOLD}📊 RESULTADO DEL ANÁLISIS:{Colors.END}")
        print(f"Nivel de seguridad: {result['level']}")
        print(f"Puntuación: {Colors.YELLOW}{result['score']}/6{Colors.END}")
        print(f"\n{Colors.BOLD}📋 Detalles:{Colors.END}")
        for item in result['feedback']:
            print(f"  {item}")
    
    def run_option_2(self):
        """Ejecuta la opción 2: Generar contraseña segura"""
        print(f"\n{Colors.GREEN}🎲 GENERADOR DE CONTRASEÑAS{Colors.END}")
        print(f"{Colors.PURPLE}{'-' * 30}{Colors.END}")
        
        try:
            length = input("Longitud de contraseña (16): ").strip() or "16"
            length = int(length)
            
            if length < 4:
                print(f"{Colors.RED}❌ La longitud mínima es 4 caracteres{Colors.END}")
                return
            
            symbols = input("¿Incluir símbolos especiales? (s/n): ").strip().lower()
            include_symbols = symbols in ['s', 'si', 'y', 'yes', '']
            
            password = self.generate_password(length, include_symbols)
            
            print(f"\n{Colors.BOLD}🔐 CONTRASEÑA GENERADA:{Colors.END}")
            print(f"  {Colors.CYAN}{password}{Colors.END}")
            
            # Análisis automático
            result = self.analyze_password(password)
            print(f"\n📊 Nivel de seguridad: {result['level']}")
            
        except ValueError:
            print(f"{Colors.RED}❌ Longitud inválida{Colors.END}")
    
    def run_option_4(self):
        """Ejecuta la opción 4: Verificar filtración HIBP"""
        print(f"\n{Colors.BLUE}🌐 VERIFICACIÓN DE FILTRACIONES{Colors.END}")
        print(f"{Colors.PURPLE}{'-' * 30}{Colors.END}")
        
        password = getpass.getpass("Ingresa la contraseña a verificar: ")
        if not password:
            print(f"{Colors.RED}❌ No se ingresó contraseña{Colors.END}")
            return
        
        self.check_hibp(password)
    
    def run_option_5(self):
        """Ejecuta la opción 5: Convertir frase a contraseña"""
        print(f"\n{Colors.YELLOW}📝 CONVERTIDOR FRASE → CONTRASEÑA{Colors.END}")
        print(f"{Colors.PURPLE}{'-' * 30}{Colors.END}")
        
        phrase = input("Ingresa una frase fácil de recordar: ").strip()
        if not phrase:
            print(f"{Colors.RED}❌ No se ingresó frase{Colors.END}")
            return
        
        password = self.phrase_to_password(phrase)
        
        print(f"\n{Colors.BOLD}🔄 CONVERSIÓN:{Colors.END}")
        print(f"  Frase original: {Colors.CYAN}{phrase}{Colors.END}")
        print(f"  Contraseña: {Colors.GREEN}{password}{Colors.END}")
        
        # Análisis automático
        result = self.analyze_password(password)
        print(f"\n📊 Nivel de seguridad: {result['level']}")
    
    def run(self):
        """Función principal del programa"""
        while True:
            self.show_banner()
            choice = input(f"{Colors.BOLD}Selecciona una opción: {Colors.END}").strip()
            
            if choice == '1':
                self.run_option_1()
            elif choice == '2':
                self.run_option_2()
            elif choice == '3':
                self.manage_passwords()
            elif choice == '4':
                self.run_option_4()
            elif choice == '5':
                self.run_option_5()
            elif choice == '0':
                print(f"\n{Colors.GREEN}👋 ¡Gracias por usar Password Tool!{Colors.END}")
                sys.exit(0)
            else:
                print(f"{Colors.RED}❌ Opción inválida{Colors.END}")
            
            input(f"\n{Colors.YELLOW}Presiona Enter para continuar...{Colors.END}")

def main():
    """Función principal"""
    try:
        # Limpiar pantalla al iniciar
        os.system('cls' if os.name == 'nt' else 'clear')
        
        tool = PasswordTool()
        tool.run()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}👋 Programa interrumpido por el usuario{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}❌ Error inesperado: {e}{Colors.END}")
        sys.exit(1)

if __name__ == "__main__":
    main()