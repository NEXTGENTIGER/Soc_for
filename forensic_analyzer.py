#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Forensic Analyzer - Outil d'analyse forensique complet
Analyse les fichiers, la mémoire, les disques et les systèmes
"""

import os
import sys
import json
import time
import magic
import hashlib
import platform
import subprocess
import datetime
import yara
import clamd
import pefile
import requests
import psutil
import socket
import struct
import binascii
import logging
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional, Union

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('forensic_analysis.log'),
        logging.StreamHandler()
    ]
)

class ForensicAnalyzer:
    def __init__(self, target: str):
        self.target = target
        self.timestamp = datetime.datetime.now().isoformat()
        self.results = {
            "tool": "forensic_analyzer",
            "timestamp": self.timestamp,
            "target": target,
            "result": {
                "scan_type": "full_forensic_analysis",
                "file_analysis": {},
                "system_analysis": {},
                "threat_analysis": {},
                "recommendations": []
            }
        }
        self.setup_environment()

    def setup_environment(self):
        """Configuration de l'environnement d'analyse"""
        try:
            # Vérification des outils nécessaires
            self.check_required_tools()
            
            # Configuration de ClamAV
            self.setup_clamav()
            
            # Chargement des règles YARA
            self.load_yara_rules()
            
            logging.info("Environnement configuré avec succès")
        except Exception as e:
            logging.error(f"Erreur lors de la configuration: {str(e)}")
            raise

    def check_required_tools(self):
        """Vérification des outils nécessaires"""
        required_tools = [
            "clamd",
            "yara",
            "volatility3",
            "exiftool",
            "fls",
            "tsk_recover"
        ]
        
        for tool in required_tools:
            try:
                subprocess.run([tool, "--version"], capture_output=True)
                logging.info(f"Outil {tool} trouvé")
            except FileNotFoundError:
                logging.warning(f"Outil {tool} non trouvé")

    def setup_clamav(self):
        """Configuration de ClamAV"""
        try:
            self.clam = clamd.ClamdUnixSocket()
            self.clam.ping()
            logging.info("ClamAV configuré avec succès")
        except Exception as e:
            logging.warning(f"ClamAV non disponible: {str(e)}")
            self.clam = None

    def load_yara_rules(self):
        """Chargement des règles YARA"""
        try:
            self.yara_rules = yara.compile('rules/malware.yar')
            logging.info("Règles YARA chargées avec succès")
        except Exception as e:
            logging.error(f"Erreur lors du chargement des règles YARA: {str(e)}")
            raise

    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Analyse complète d'un fichier"""
        try:
            file_info = self.get_file_info(file_path)
            static_analysis = self.static_analysis(file_path)
            dynamic_analysis = self.dynamic_analysis(file_path)
            behavior_analysis = self.behavior_analysis(file_path)
            
            return {
                "basic_info": file_info,
                "static_analysis": static_analysis,
                "dynamic_analysis": dynamic_analysis,
                "behavior_analysis": behavior_analysis
            }
        except Exception as e:
            logging.error(f"Erreur lors de l'analyse du fichier {file_path}: {str(e)}")
            return {}

    def get_file_info(self, file_path: str) -> Dict[str, Any]:
        """Obtention des informations de base du fichier"""
        try:
            stat = os.stat(file_path)
            mime = magic.Magic(mime=True)
            file_type = mime.from_file(file_path)
            
            # Calcul des hashes
            md5 = hashlib.md5()
            sha256 = hashlib.sha256()
            
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    md5.update(chunk)
                    sha256.update(chunk)
            
            return {
                "name": os.path.basename(file_path),
                "path": file_path,
                "size": stat.st_size,
                "type": file_type,
                "md5": md5.hexdigest(),
                "sha256": sha256.hexdigest(),
                "permissions": oct(stat.st_mode)[-3:],
                "created": datetime.datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "modified": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "accessed": datetime.datetime.fromtimestamp(stat.st_atime).isoformat()
            }
        except Exception as e:
            logging.error(f"Erreur lors de l'obtention des informations du fichier: {str(e)}")
            return {}

    def static_analysis(self, file_path: str) -> Dict[str, Any]:
        """Analyse statique du fichier"""
        try:
            results = {
                "clamav": self.scan_clamav(file_path),
                "yara": self.scan_yara(file_path),
                "pe_analysis": self.analyze_pe(file_path) if file_path.endswith('.exe') else None,
                "strings": self.extract_strings(file_path),
                "entropy": self.calculate_entropy(file_path),
                "packer_detection": self.detect_packer(file_path),
                "crypto_analysis": self.analyze_crypto(file_path)
            }
            return results
        except Exception as e:
            logging.error(f"Erreur lors de l'analyse statique: {str(e)}")
            return {}

    def dynamic_analysis(self, file_path: str) -> Dict[str, Any]:
        """Analyse dynamique du fichier"""
        try:
            results = {
                "network_behavior": self.analyze_network_behavior(file_path),
                "file_operations": self.analyze_file_operations(file_path),
                "registry_operations": self.analyze_registry_operations(file_path),
                "process_behavior": self.analyze_process_behavior(file_path)
            }
            return results
        except Exception as e:
            logging.error(f"Erreur lors de l'analyse dynamique: {str(e)}")
            return {}

    def behavior_analysis(self, file_path: str) -> Dict[str, Any]:
        """Analyse du comportement"""
        try:
            results = {
                "suspicious_activities": self.detect_suspicious_activities(file_path),
                "malware_indicators": self.detect_malware_indicators(file_path),
                "anti_analysis": self.detect_anti_analysis(file_path),
                "persistence": self.detect_persistence(file_path)
            }
            return results
        except Exception as e:
            logging.error(f"Erreur lors de l'analyse comportementale: {str(e)}")
            return {}

    def scan_clamav(self, file_path: str) -> Dict[str, Any]:
        """Scan avec ClamAV"""
        try:
            if self.clam:
                result = self.clam.scan(file_path)
                return {
                    "status": "success",
                    "result": result
                }
            return {
                "status": "error",
                "message": "ClamAV non disponible"
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }

    def scan_yara(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan avec YARA"""
        try:
            matches = self.yara_rules.match(file_path)
            return [{
                "rule": match.rule,
                "strings": match.strings,
                "meta": match.meta
            } for match in matches]
        except Exception as e:
            logging.error(f"Erreur lors du scan YARA: {str(e)}")
            return []

    def analyze_pe(self, file_path: str) -> Dict[str, Any]:
        """Analyse des fichiers PE"""
        try:
            pe = pefile.PE(file_path)
            return {
                "machine_type": hex(pe.FILE_HEADER.Machine),
                "timestamp": datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat(),
                "sections": [{
                    "name": section.Name.decode().rstrip('\x00'),
                    "virtual_address": hex(section.VirtualAddress),
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "entropy": self.calculate_section_entropy(section)
                } for section in pe.sections],
                "imports": self.get_pe_imports(pe),
                "exports": self.get_pe_exports(pe),
                "resources": self.get_pe_resources(pe)
            }
        except Exception as e:
            logging.error(f"Erreur lors de l'analyse PE: {str(e)}")
            return {}

    def analyze_system(self) -> Dict[str, Any]:
        """Analyse du système"""
        try:
            return {
                "memory_analysis": self.analyze_memory(),
                "disk_analysis": self.analyze_disk(),
                "network_analysis": self.analyze_network(),
                "process_analysis": self.analyze_processes()
            }
        except Exception as e:
            logging.error(f"Erreur lors de l'analyse système: {str(e)}")
            return {}

    def analyze_memory(self) -> Dict[str, Any]:
        """Analyse de la mémoire"""
        try:
            memory_info = psutil.virtual_memory()
            return {
                "total": memory_info.total,
                "available": memory_info.available,
                "used": memory_info.used,
                "free": memory_info.free,
                "percent": memory_info.percent
            }
        except Exception as e:
            logging.error(f"Erreur lors de l'analyse mémoire: {str(e)}")
            return {}

    def analyze_disk(self) -> Dict[str, Any]:
        """Analyse des disques"""
        try:
            disk_info = []
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disk_info.append({
                        "device": partition.device,
                        "mountpoint": partition.mountpoint,
                        "fstype": partition.fstype,
                        "total": usage.total,
                        "used": usage.used,
                        "free": usage.free,
                        "percent": usage.percent
                    })
                except Exception:
                    continue
            return {"partitions": disk_info}
        except Exception as e:
            logging.error(f"Erreur lors de l'analyse disque: {str(e)}")
            return {}

    def analyze_network(self) -> Dict[str, Any]:
        """Analyse du réseau"""
        try:
            network_info = {
                "connections": [],
                "interfaces": []
            }
            
            # Connexions
            for conn in psutil.net_connections():
                try:
                    network_info["connections"].append({
                        "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                        "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        "status": conn.status,
                        "pid": conn.pid
                    })
                except Exception:
                    continue
            
            # Interfaces
            for interface, addrs in psutil.net_if_addrs().items():
                try:
                    network_info["interfaces"].append({
                        "name": interface,
                        "addresses": [{
                            "family": str(addr.family),
                            "address": addr.address,
                            "netmask": addr.netmask,
                            "broadcast": addr.broadcast
                        } for addr in addrs]
                    })
                except Exception:
                    continue
            
            return network_info
        except Exception as e:
            logging.error(f"Erreur lors de l'analyse réseau: {str(e)}")
            return {}

    def analyze_processes(self) -> List[Dict[str, Any]]:
        """Analyse des processus"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_percent', 'cpu_percent']):
                try:
                    processes.append(proc.info)
                except Exception:
                    continue
            return processes
        except Exception as e:
            logging.error(f"Erreur lors de l'analyse des processus: {str(e)}")
            return []

    def generate_report(self) -> Dict[str, Any]:
        """Génération du rapport complet"""
        try:
            # Analyse des fichiers
            if os.path.isfile(self.target):
                self.results["result"]["file_analysis"] = self.analyze_file(self.target)
            elif os.path.isdir(self.target):
                self.results["result"]["file_analysis"] = {
                    "directory": self.target,
                    "files": [self.analyze_file(os.path.join(self.target, f)) 
                             for f in os.listdir(self.target)]
                }
            
            # Analyse du système
            self.results["result"]["system_analysis"] = self.analyze_system()
            
            # Analyse des menaces
            self.results["result"]["threat_analysis"] = {
                "malware_indicators": self.detect_malware_indicators(self.target),
                "suspicious_activities": self.detect_suspicious_activities(self.target),
                "security_vulnerabilities": self.detect_vulnerabilities(self.target)
            }
            
            # Recommandations
            self.results["result"]["recommendations"] = self.generate_recommendations()
            
            return self.results
        except Exception as e:
            logging.error(f"Erreur lors de la génération du rapport: {str(e)}")
            return {}

    def save_report(self, output_path: str):
        """Sauvegarde du rapport"""
        try:
            report = self.generate_report()
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
            logging.info(f"Rapport sauvegardé dans {output_path}")
        except Exception as e:
            logging.error(f"Erreur lors de la sauvegarde du rapport: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description='Forensic Analyzer - Outil d\'analyse forensique')
    parser.add_argument('target', help='Fichier ou dossier à analyser')
    parser.add_argument('--output', help='Chemin du fichier de sortie', default='report.json')
    parser.add_argument('--verbose', action='store_true', help='Mode verbeux')
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        analyzer = ForensicAnalyzer(args.target)
        analyzer.save_report(args.output)
    except Exception as e:
        logging.error(f"Erreur lors de l'analyse: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()           