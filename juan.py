import tkinter as tk
import paramiko
import socket
import time

class RouterAccess:
    def _init_(self, master):
        self.master = master
        self.master.title('Acceso al Router')
        
        # Crear widgets
        self.label_ip = tk.Label(self.master, text='IP del Router:')
        self.entry_ip = tk.Entry(self.master)
        self.label_user = tk.Label(self.master, text='Usuario:')
        self.entry_user = tk.Entry(self.master)
        self.label_pw = tk.Label(self.master, text='Contraseña:')
        self.entry_pw = tk.Entry(self.master, show='*')
        self.button_access = tk.Button(self.master, text='Acceder', command=self.access_router)
        self.textbox_command = tk.Text(self.master, state='disabled', height=20, width=80)
        
        # Posicionar widgets
        self.label_ip.grid(row=0, column=0)
        self.entry_ip.grid(row=0, column=1)
        self.label_user.grid(row=1, column=0)
        self.entry_user.grid(row=1, column=1)
        self.label_pw.grid(row=2, column=0)
        self.entry_pw.grid(row=2, column=1)
        self.button_access.grid(row=3, column=0, columnspan=2)
        self.textbox_command.grid(row=4, column=0, columnspan=2)
        
    def access_router(self):
        # Obtener la IP, el usuario y la contraseña del router
        ip = self.entry_ip.get()
        user = self.entry_user.get()
        pw = self.entry_pw.get()
        
        # Conectar al router y lanzar comando export por ssh
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=user, password=pw, timeout=5)

            stdin, stdout, stderr = ssh.exec_command('ip firewall address-list export')
            time.sleep(2)
            rsc_content = stdout.read().decode()

            ssh.close()
            
            # Mostrar el resultado en el cuadro de texto
            self.textbox_command.configure(state='normal')
            self.textbox_command.delete(1.0, tk.END)
            self.textbox_command.insert(tk.END, rsc_content)
            self.textbox_command.configure(state='disabled')
            
        except paramiko.ssh_exception.AuthenticationException as e:
            print('Autenticacion fallida')
        except socket.timeout as e:
            print("Error de Timeout: No se pudo establecer una conexión con el router en el tiempo especificado.")
        except socket.error as e:
            print("Error de conexión: No se pudo establecer una conexión con el router. Verifique la dirección IP.")
        except Exception as e:
            print(f"Error desconocido: {e}")

if __name__ == '__main__':
    root = tk.Tk()
    app = RouterAccess(root)
    root.mainloop()