#!/usr/bin/env python3

import os
import subprocess
import json
import requests
from datetime import datetime

class ContainerAuditor:
    def _init_(self):
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "findings": []
        }
    
    def check_privileged(self):
        """Проверка привилегированного контейнера"""
        try:
            with open('/proc/self/status') as f:
                for line in f:
                    if line.startswith('CapEff:'):
                        caps = line.split()[1]
                        if caps == '0000003fffffffff':
                            self.add_finding("PRIVILEGED_CONTAINER", 
                                           "Контейнер запущен с --privileged", "HIGH")
                        break
        except:
            pass
    
    def check_docker_socket(self):
        """Проверка доступа к Docker socket"""
        if os.path.exists('/var/run/docker.sock'):
            if os.access('/var/run/docker.sock', os.R_OK):
                self.add_finding("DOCKER_SOCKET_ACCESS",
                               "Доступ к Docker socket", "CRITICAL")
    
    def check_mounts(self):
        """Проверка опасных монтирований"""
        mounts = []
        try:
            with open('/proc/mounts') as f:
                mounts = f.read()
        except:
            pass
        
        dangerous_mounts = ['/proc', '/sys', '/dev', '/var/run']
        for mount in dangerous_mounts:
            if mount in mounts:
                self.add_finding("DANGEROUS_MOUNT",
                               f"Монтирование {mount}", "MEDIUM")
    
    def check_cloud_metadata(self):
        """Проверка доступа к облачным метаданным"""
        endpoints = [
            'http://169.254.169.254/',
            'http://metadata.google.internal/',
            'http://169.254.169.254/metadata/'
        ]
        
        for endpoint in endpoints:
            try:
                resp = requests.get(endpoint, timeout=2)
                if resp.status_code == 200:
                    self.add_finding("CLOUD_METADATA_ACCESS",
                                   f"Доступ к {endpoint}", "CRITICAL")
            except:
                pass
    
    def check_suid_binaries(self):
        """Поиск SUID бинарников"""
        try:
            result = subprocess.run(['find', '/', '-perm', '-4000', '-type', 'f',
                                   '!', '-path', '/proc/*', '2>/dev/null'],
                                  capture_output=True, text=True)
            suid_bins = result.stdout.strip().split('\n')
            
            dangerous = ['mount', 'umount', 'chroot', 'pkexec', 'passwd']
            for bin in suid_bins:
                for d in dangerous:
                    if d in bin:
                        self.add_finding("DANGEROUS_SUID",
                                       f"Опасный SUID: {bin}", "HIGH")
        except:
            pass
    
    def add_finding(self, title, description, severity):
        self.results["findings"].append({
            "title": title,
            "description": description,
            "severity": severity
        })
    
    def run_all_checks(self):
        checks = [
            self.check_privileged,
            self.check_docker_socket,
            self.check_mounts,
            self.check_cloud_metadata,
            self.check_suid_binaries
        ]
        
        for check in checks:
            try:
                check()
            except Exception as e:
                print(f"Error in check: {e}")
        
        return self.results
    
    def generate_report(self):
        report = self.run_all_checks()
        
        print("=" * 60)
        print("CONTAINER SECURITY AUDIT REPORT")
        print("=" * 60)
        
        for finding in report["findings"]:
            print(f"\n[{finding['severity']}] {finding['title']}")
            print(f"  {finding['description']}")
        
        print(f"\nTotal findings: {len(report['findings'])}")
        
        # Сохраняем в файл
        with open('/tmp/container_audit.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        return report

if _name_ == "_main_":
    auditor = ContainerAuditor()
    auditor.generate_report()
