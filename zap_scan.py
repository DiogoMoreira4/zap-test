# Intelligent System for Automation of Security Audits (SIAAS)
# Agent - Scan module
# By Diogo da Silva Moreira, 2024

import siaas_aux
import logging
import os
import sys
import pprint
import time
import configparser
import yaml
import json
import subprocess
import time
import psutil
from zapv2 import ZAPv2


#funciona
def read_targets_from_ini(ini_file):
    config = configparser.ConfigParser()
    config.read(ini_file)
    targets = []
    
    targetsAux = dict(config.items('Targets'))
    
    for targetName, targetInfo in targetsAux.items():
        name = targetName
        
        aux = json.loads(targetInfo)
        
        url = aux.get("url")
        username = aux.get("username")
        password = aux.get("password")
        loginPage = aux.get("loginPage")
        
        target = {
            name : {
                'url': url,
                'username': username,
                'password': password,
                'loginURL': loginPage
            }
        }
        
        targets.append(target)
    #print("Li o ficheiro .ini e tenho estes targets", targets)
    return targets
                
            
#funciona
def update_automation_plan(template_yaml_file, target, output_yaml_file):
    
    
    main_key = next(iter(target))
   
    
    with open(template_yaml_file, 'r') as yaml_file:
        dados_yaml = yaml.safe_load(yaml_file)
        
    if 'env' in dados_yaml and 'contexts' in dados_yaml['env']:
        for aux in dados_yaml['env']['contexts']:
            
            aux['name'] = main_key
            aux['urls'] = [target[main_key]['url']]
            aux['includePaths'] = [target[main_key]['url']]
            aux['authentication']['parameters']['loginPageUrl'] = target[main_key]['loginURL']
            aux['users'][0]['name'] = target[main_key]['username']
            aux['users'][0]['credentials']['username'] = target[main_key]['username']
            aux['users'][0]['credentials']['password'] = target[main_key]['password']
        
                        
    if 'jobs' in dados_yaml:
        
        #requestor
        dados_yaml['jobs'][1]['parameters']['user'] = target[main_key]['username']
        dados_yaml['jobs'][1]['requests'][0]['url'] = target[main_key]['loginURL']
        
        #spider
        dados_yaml['jobs'][2]['parameters']['context'] = main_key
        dados_yaml['jobs'][2]['parameters']['user'] = target[main_key]['username']
        
        #spiderAjax
        dados_yaml['jobs'][3]['parameters']['context'] = main_key
        dados_yaml['jobs'][3]['parameters']['user'] = target[main_key]['username']
        
        #delay
        
        #passiveScan-wait
        
        #activeScan
        dados_yaml['jobs'][6]['parameters']['context'] = main_key
        dados_yaml['jobs'][6]['parameters']['user'] = target[main_key]['username']
        
        #report
        #dados_yaml['jobs'][7]['parameters']['reportFile'] = main_key
        
         
    with open(output_yaml_file, 'w') as yaml_file:
        yaml.dump(dados_yaml, yaml_file)   


def shutdown_zap(zap, zap_process):
    zap.core.shutdown()
    zap_process.terminate()
    zap_process.wait()


def check_system_resources(min_memory_gb, min_cpu_count):
    memory = psutil.virtual_memory()
    available_memory_gb = memory.available / (1024 ** 3)
    cpu_count = psutil.cpu_count(logical=False)
    
    if available_memory_gb < min_memory_gb or cpu_count < min_cpu_count:
        raise SystemError(f"Insufficient resources: Available memory: {available_memory_gb} GB, CPU count: {cpu_count}")

def iniciar_zap_corretamente(zap_path, zap_port, zap_home):
    zap_process = start_zap(zap_path, zap_port, zap_home)
    zap = ZAPv2(apikey='918261012', proxies={'http': f'http://127.0.0.1:{zap_port}', 'https': f'http://127.0.0.1:{zap_port}'})
    time.sleep(120)
    print("Vou desligar")
    zap.core.shutdown()
    zap_process.terminate()
    zap_process.wait()
    

def start_zap(zap_path, zap_port, zap_home):
    
    cmd = [zap_path, '-daemon', '-port', zap_port,'-dir' ,zap_home,'-config','api.key=123456789']
    zap_process = subprocess.Popen(cmd)
    time.sleep(60)  # Give ZAP some time to start
    print("Criei uma nova instancia ZAP na porta", zap_port, zap_home)
    return zap_process


def run_automation_plan(zap, yaml_plan):
    print(yaml_plan)
    planId = zap.automation.run_plan("/home/vboxuser/siaas-agent/NewPlan1.yaml")
    print('Comecei o plano de automacao')
    # Wait for the automation plan to complete
    while zap.automation.plan_progress(planId)['finished'] == "":
        print('The Automation Plan with Id', planId,'is running...')
        print("Estou aqui e vou esperar 10 min")        
        time.sleep(600)


def scan_target(target, zap_path, template_yaml_file, zap_port, zap_home):
    output_yaml_file = f'automation_plan_{zap_port}.yaml'
    update_automation_plan(template_yaml_file, target, output_yaml_file)
    
    # Start ZAP
    zap_process = start_zap(zap_path, zap_port, zap_home)
    print("Estou a escuta!!!")
    zap = ZAPv2(apikey='123456789', proxies={'http': f'http://127.0.0.1:{zap_port}', 'https': f'http://127.0.0.1:{zap_port}'})
    print("Conectei-me ao zap")
    # Run the automation plan
    #run_automation_plan(zap, output_yaml_file)
    run_automation_plan(zap, output_yaml_file)
    
    # Shutdown ZAP
    shutdown_zap(zap, zap_process)
    
    os.remove(output_yaml_file)
    

def main(ini_file, template_yaml_file, zap_path):
    min_memory_gb = 2  # Minimum memory per ZAP instance
    min_cpu_count = 1  # Minimum CPU count per ZAP instance
    
    targets = read_targets_from_ini(ini_file)
    zap_port_base = 8091  # Starting port for ZAP instances
    
    for idx, target in enumerate(targets):
        zap_port = str(zap_port_base + idx)
        zap_home = "/home/vboxuser/zaproxy/instance1"
        
        # Check system resources before starting each ZAP instance
        check_system_resources(min_memory_gb, min_cpu_count)
        
        scan_target(target, zap_path, template_yaml_file, zap_port, zap_home)
        #iniciar_zap_corretamente(zap_path, zap_port, zap_home)
        
if __name__ == "__main__":
    
    log_level = logging.INFO
    logging.basicConfig(
        format='%(asctime)s %(levelname)-5s %(filename)s [%(threadName)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=log_level)

    ini_file = os.path.join('conf', 'siaas_zap_agent.ini')
    template_yaml_file = '/home/vboxuser/siaas-agent/NewPlan.yaml'
    zap_path = '/home/vboxuser/zaproxy/zap.sh'
    main(ini_file, template_yaml_file, zap_path)

    print('\nAll done. Bye!\n')
    
