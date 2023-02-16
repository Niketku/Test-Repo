
#!/usr/bin/python

import optparse
import ast
import json
from utils import getConfigData
from pprint import pprint
from cisco_cms_snmp import snmp_session
from Cred import snmph_from_cred_array
from pprint import pprint


ENHANCED_MIB_MEMPOOL_TYPE = ".1.3.6.1.4.1.9.9.221.1.1.1.1.2"

# CISCO-MEMORY-POOL-MIB: ciscoMemoryPoolName: valid values{1:  processor memory, 2:  i/o memory, 3:  pci memory, ...}
OLD_MEMORY_POOL_NAME = ".1.3.6.1.4.1.9.9.48.1.1.1.2"

# CISCO-FIREPOWER-SM-MIB: cfprSmMonitorDn: valid values {?}
FirePower_MemUsedKb = '.1.3.6.1.4.1.9.9.826.1.71.20.1.2'

# CISCO-PROCESS-MIB: cpmCPUMemoryUsed
PROCESS_cpmCPUMemoryUsed = '.1.3.6.1.4.1.9.9.109.1.1.1.1.12'

# CISCO-MEMORY-POOL-MIB: cpmCPUMemoryUsed
oldMib_oids = {
               'used': '.1.3.6.1.4.1.9.9.48.1.1.1.5',
               'free': '.1.3.6.1.4.1.9.9.48.1.1.1.6'
               }

# CISCO-ENHANCED-MEMPOOL-MIB:cempMemPoolValid (6)  cempMemPoolUsed (7), cempMemPoolFree (8)
newMib_oids = {
               'used': '.1.3.6.1.4.1.9.9.221.1.1.1.1.7',
               'free': '.1.3.6.1.4.1.9.9.221.1.1.1.1.8',
               'HCused': '.1.3.6.1.4.1.9.9.221.1.1.1.1.18',
               'HCfree': '.1.3.6.1.4.1.9.9.221.1.1.1.1.20',
               }

# CISCO-FIREPOWER-SM-MIB::cfprSmMonitorMemFreeKb(9), cfprSmMonitorMemUsedKb(11), cfprSmMonitorMemTotalKb(10), cfprSmMonitorMemAppTotalKb(14)
firepower_oids = {'free': '.1.3.6.1.4.1.9.9.826.1.71.20.1.9',
                  'used': '.1.3.6.1.4.1.9.9.826.1.71.20.1.11',
                  }

# CISCO-PROCESS-MIB cpmCPUTotalPhysicalIndex(2), cpmCPUMemoryUsed(12), cpmCPUMemoryFree(13)
process_mib_oids = {'index': '.1.3.6.1.4.1.9.9.109.1.1.1.1.2',
                    'used': '.1.3.6.1.4.1.9.9.109.1.1.1.1.12',
                    'free': '.1.3.6.1.4.1.9.9.109.1.1.1.1.13',
                    'label': '.1.3.6.1.2.1.47.1.1.1.1.7'}


# snmp_h = em7_snippets.snmph_from_cred_id(self.cred_details['cred_id'], self.ip)

# collection_objects
snippet_arguments = {
    'IO Memory Used': [],
    'IO Memory Free': [],
    'Processor Memory Used': [],
    'Processor Memory Free':[],
    'Total Memory Free': [],
    'Total Memory Used':[],
    'Total Memory Used %':[]
    }

labels = []

pre_obj= {'io_memUsed': 'IO Memory Used', 'io_memFree': 'IO Memory Free', 'proc_memUsed': 'Processor Memory Used', 'proc_memFree': 'Processor Memory Free', 'total_memUsed': 'Total Memory Used', 'total_memFree': 'Total Memory Free'}

entPhysicalName_oid = '.1.3.6.1.2.1.47.1.1.1.1.7'
mib_toUse = None

#####
# Now we are going to try to figure out which MIB holds mempool descriptions. This will provide a mapping between indexes and the memory type.
# Remember, the OID contains the pysical index and the memory type index. The value is the memory type of that final index.
#####

def is_oid_cacheable(oid):
    is_cacheable = all(not oid.startswith(z) for z in (list(oldMib_oids.values()) + list(newMib_oids.values()) + list(firepower_oids.values())))
    return is_cacheable

def get_multi_with_cache(oidlist):
    chunk_size = 20
    chunks = [oidlist[i:i + chunk_size] for i in range(0, len(oidlist), chunk_size)]
    all_result = None

    for chunk in chunks:
        chunk_result = get_multi_with_cache_split(chunk)

        if chunk_result is not None:
            if all_result is not None:
                all_result = all_result + chunk_result
            else:
                all_result = chunk_result
    return all_result


def get_multi_with_cache_split(oidlist):
    cacheable_oids = [oid for oid in oidlist if is_oid_cacheable(oid)]
    cacheable_result = snmp_handler.get_multi(cacheable_oids)
    uncacheable_oids = [oid for oid in oidlist if oid not in cacheable_oids]
    uncacheable_result = snmp_handler.get_multi(uncacheable_oids)

    if uncacheable_result is None and cacheable_result is None:
        return None
    elif uncacheable_result is None:
        uncacheable_result = []
    elif cacheable_result is None:
        cacheable_result = []

    result_dict = {oid: val for (oid, val) in (cacheable_result + uncacheable_result)}
    result = [(oid, result_dict[oid]) for oid in oidlist]
    return result


def get_oid_value(oid):
    result = None
    if fall_back_to_get:
        get_result = snmp_handler.get(oid)
        if get_result:
            result = str(get_result[0].decode('ascii'))
    else:
        if oid in all_oids_response:
            result = all_oids_response[oid]

    return result

def fill_result_handler(entry):
    for key, val in entry.items():
        if key in pre_obj:
            snippet_arguments[pre_obj[key]].append(('.'+ entry['index'], val))
    labels.append(('.'+ entry['index'], entry['memLabel']))
    return

def parse_args():
    parser = optparse.OptionParser()
    parser.add_option(  "-H","--host",
                                            help="Host address"
                                    )

    options, args = parser.parse_args()
#   options.oidjson = is_json(options.oidjson)
    return options

cred_details = {'snmp_version': 3, 'snmpv3_engine_id': '', 'cred_timeout': 1500, 'cred_id': 430, 'snmpv3_sec_level': 'authPriv', 'snmp_retries': 1, 'snmp_rw_community': '', 'snmp_ro_community': '', 'cred_port': 161, 'cred_type': 1, 'snmpv3_auth_proto': 'MD5', 'cred_name': 'SNMP V3 New_vdya', 'snmpv3_priv_pwd': 'snmpPAE22ro!', 'snmpv3_priv_proto': 'DES', 'sub_type': '', 'cred_pwd': 'snmpPAE22ro!', 'snmpv3_context': '', 'cred_host': '', 'cred_user': 'paesnmpv3r'}

host = parse_args().host

snmp_h = getConfigData(host,cred_details)

snmp_handler = snmph_from_cred_array(cred_details, host)

description = snmp_h.snmpWalk(ENHANCED_MIB_MEMPOOL_TYPE)
oids_to_get = []

# check MIB CISCO-ENHANCED-MEMPOOL-MIB: cempMemPoolType
if description:
    mib_toUse = ENHANCED_MIB_MEMPOOL_TYPE
    for key, value in description:
        if value is None:
            continue

        processor_temp = key.split('.')
        entPhysicalIndex = processor_temp[-2]
        cempMemPoolIndex = processor_temp[-1]
        index = entPhysicalIndex + '.' + cempMemPoolIndex
        oids_to_get += [
            newMib_oids['used'] + "." + index,
            newMib_oids['free'] + "." + index,
            newMib_oids['HCused'] + "." + index,
            newMib_oids['HCfree'] + "." + index,
            entPhysicalName_oid + "." + entPhysicalIndex
        ]

# CISCO-MEMORY-POOL-MIB: ciscoMemoryPoolName
if not description:
    description = snmp_h.snmpWalk(OLD_MEMORY_POOL_NAME)
    if description:
        mib_toUse = OLD_MEMORY_POOL_NAME
        for key, value in description:
            if value is None:
                continue
            processor_temp = key.split('.')
            index = processor_temp[-1]
            oids_to_get += [
                oldMib_oids['used'] + "." + index,
                oldMib_oids['free'] + "." + index]

# CISCO-FIREPOWER-SM-MIB: cfprSmMonitorDn:
if not description:
    description = snmp_h.snmpWalk(FirePower_MemUsedKb)
    if description:
        mib_toUse = FirePower_MemUsedKb
        for key, value in description:
            index = key.split('.')[-1]
            oids_to_get += [firepower_oids['free'] + "." + index,
                            firepower_oids['used'] + "." + index]

# CISCO-PROCESS-MIB PROCESS_PhysicalIndex
if not description or len(description) <= 0:
    description = snmp_h.snmpWalk(PROCESS_cpmCPUMemoryUsed)
    if description:
        mib_toUse = PROCESS_cpmCPUMemoryUsed
        for key, value in description:
            index = key.rsplit('.', 1)[-1]
            oids_to_get += [process_mib_oids['free'] + "." + index,
                            process_mib_oids['index'] + "." + index]

if not description:
    raise SnippetException("No data collected.")


oids_to_get = list(set(oids_to_get))

all_oids_response = {oid: val for oid, val in get_multi_with_cache(oids_to_get)}

if any(all_oids_response.values()):
    fall_back_to_get = False;
else:
    fall_back_to_get = True;

ent_physical_name_list = {}

# Collecting data from CISCO-ENHANCED-MEMPOOL-MIB
if mib_toUse == ENHANCED_MIB_MEMPOOL_TYPE:
    entity_names = {}
    toDelete = []
    for key, value in description:
        entPhysicalIndex = key.split('.')[-2]
        temp = get_oid_value(entPhysicalName_oid + '.' + entPhysicalIndex)
        if temp:
            entity_names[entPhysicalIndex] = temp
        else:
            toDelete.append(key)

    # delete oids from main walk if null
    for keyDel in toDelete:
        for key, value in description:
            if keyDel == key:
                description.remove((key, value))

    for key, value in description:

        if value is None:
            continue

        processor_temp = key.split('.')

        entPhysicalIndex = processor_temp[-2]
        cempMemPoolIndex = processor_temp[-1]

        # Index structure: entPhysicalIndex.cempMemPoolIndex
        index = entPhysicalIndex + '.' + cempMemPoolIndex
        entPhysicalName = entity_names[entPhysicalIndex]

        if not entPhysicalName in ent_physical_name_list.keys():
            ent_physical_name_list[entPhysicalName] = {
                'index': entPhysicalIndex,
                'memLabel': entPhysicalName,
                'total_memUsed': 0,
                'total_memFree': 0
            }

        if value == '2':  # Process memory
            # The original data: true(1) and false(2). In this case this was changed to: true(1) and false(0).
    #        temp_process_valid = get_oid_value(newMib_oids['valid'] + "." + index)
    #        if temp_process_valid is not None:
    #            ent_physical_name_list[entPhysicalName]['proc_memValid'] = (1 if temp_process_valid in ('true', 1, True, '1') else 0)

            temp_process_used = get_oid_value(newMib_oids['HCused'] + "." + index)
            if temp_process_used is None:
                temp_process_used = get_oid_value(newMib_oids['used'] + "." + index)
            if temp_process_used is not None:
                aux_process_used = int(temp_process_used)
                ent_physical_name_list[entPhysicalName]['proc_memUsed'] = aux_process_used
                ent_physical_name_list[entPhysicalName]['total_memUsed'] += aux_process_used

            temp_process_free = get_oid_value(newMib_oids['HCfree'] + "." + index)
            if temp_process_free is None:
                temp_process_free = get_oid_value(newMib_oids['free'] + "." + index)
            if temp_process_free is not None:
                aux_process_free = int(temp_process_free)
                ent_physical_name_list[entPhysicalName]['proc_memFree'] = aux_process_free
                ent_physical_name_list[entPhysicalName]['total_memFree'] += aux_process_free

        elif value == '3':  # IO memory
            ## The original data: true(1) and false(2). In this case this was changed to: true(1) and false(0).
    #        temp_io_valid = get_oid_value(newMib_oids['valid'] + "." + index)
    #        if temp_io_valid is not None:
    #            ent_physical_name_list[entPhysicalName]['io_memValid'] = (1 if temp_io_valid in ('true', 1, True, '1') else 0)

            temp_io_used = get_oid_value(newMib_oids['HCused'] + "." + index)
            if temp_io_used is None:
                temp_io_used = get_oid_value(newMib_oids['used'] + "." + index)
            if temp_io_used is not None:
                aux_io_used = int(temp_io_used)
                ent_physical_name_list[entPhysicalName]['io_memUsed'] = aux_io_used
                ent_physical_name_list[entPhysicalName]['total_memUsed'] += aux_io_used

            temp_io_free = get_oid_value(newMib_oids['HCfree'] + "." + index)
            if temp_io_free is None:
                temp_io_free = get_oid_value(newMib_oids['free'] + "." + index)
            if temp_io_free is not None:
                aux_io_free = int(temp_io_free)
                ent_physical_name_list[entPhysicalName]['io_memFree'] = aux_io_free
                ent_physical_name_list[entPhysicalName]['total_memFree'] += aux_io_free

        else:
            temp_total_used = get_oid_value(newMib_oids['HCused'] + "." + index)
            if temp_total_used is None:
                temp_total_used = get_oid_value(newMib_oids['used'] + "." + index)
            if temp_total_used is not None:
                ent_physical_name_list[entPhysicalName]['total_memUsed'] += int(temp_total_used)

            temp_total_free = get_oid_value(newMib_oids['HCfree'] + "." + index)
            if temp_total_free is None:
                temp_total_free = get_oid_value(newMib_oids['free'] + "." + index)
            if temp_total_free is not None:
                ent_physical_name_list[entPhysicalName]['total_memFree'] += int(temp_total_free)

    print(ent_physical_name_list)
elif mib_toUse == OLD_MEMORY_POOL_NAME:

    entPhysicalName = 'Memory Pool 2'
    ent_physical_name_list[entPhysicalName] = {
        'index': entPhysicalName,
        'memLabel': entPhysicalName,
        'total_memUsed': 0,
        'total_memFree': 0
    }

    for key, value in description:

        if value is None:
            continue

        processor_temp = key.split('.')
        index = processor_temp[-1]
        poolType = processor_temp[-1]

        if poolType == '1':  # Processor memory
            # The original data: true and false. In this case this was changed to: true(1) and false(0).
    #        temp_old_process_valid = get_oid_value(oldMib_oids['valid'] + "." + index)
    #        if temp_old_process_valid is not None:
    #            ent_physical_name_list[entPhysicalName]['proc_memValid'] = (1 if temp_old_process_valid in ('true', 1, True, '1') else 0)

            temp_old_process_used = get_oid_value(oldMib_oids['used'] + "." + index)
            if temp_old_process_used is not None:
                aux_old_process_used = int(temp_old_process_used)
                ent_physical_name_list[entPhysicalName]['proc_memUsed'] = aux_old_process_used
                ent_physical_name_list[entPhysicalName]['total_memUsed'] += aux_old_process_used

            temp_old_process_free = get_oid_value(oldMib_oids['free'] + "." + index)
            if temp_old_process_free is not None:
                aux_old_process_free = int(temp_old_process_free)
                ent_physical_name_list[entPhysicalName]['proc_memFree'] = aux_old_process_free
                ent_physical_name_list[entPhysicalName]['total_memFree'] += aux_old_process_free

        elif poolType == '2':  # IO memory
            # The original data: true and false. In this case this was changed to: true(1) and false(0).
    #        temp_old_io_valid = get_oid_value(oldMib_oids['valid'] + "." + index)
    #        if temp_old_io_valid is not None:
    #            ent_physical_name_list[entPhysicalName]['io_memValid'] = (1 if temp_old_io_valid in ('true', 1, True, '1') else 0)

            temp_old_io_used = get_oid_value(oldMib_oids['used'] + "." + index)
            if temp_old_io_used is not None:
                aux_old_io_used = int(temp_old_io_used)
                ent_physical_name_list[entPhysicalName]['io_memUsed'] = aux_old_io_used
                ent_physical_name_list[entPhysicalName]['total_memUsed'] += aux_old_io_used

            temp_old_io_free = get_oid_value(oldMib_oids['free'] + "." + index)
            if temp_old_io_free is not None:
                aux_old_io_free = int(temp_old_io_free)
                ent_physical_name_list[entPhysicalName]['io_memFree'] = aux_old_io_free
                ent_physical_name_list[entPhysicalName]['total_memFree'] += aux_old_io_free

        else:
            temp_old_total_used = get_oid_value(newMib_oids['used'] + "." + index)
            if temp_old_total_used is not None:
                ent_physical_name_list[entPhysicalName]['total_memUsed'] += int(temp_old_total_used)

            temp_old_total_free = get_oid_value(newMib_oids['free'] + "." + index)
            if temp_old_total_free is not None:
                ent_physical_name_list[entPhysicalName]['total_memFree'] += int(temp_old_total_free)

elif mib_toUse == FirePower_MemUsedKb:

    for key, value in description:
        index = key.split('.')[-1]
        labels.append((index, value))
        memUsedOid_withIndex = '{0}.{1}'.format(firepower_oids['used'], index)
        memFreeOid_withIndex = '{0}.{1}'.format(firepower_oids['free'], index)

        if all_oids_response:
            memUsedValue = all_oids_response.get(memUsedOid_withIndex, None)
            memFreeValue = all_oids_response.get(memFreeOid_withIndex, None)
        else:
            memUsedValue = None
            memFreeValue = None

        if memUsedValue:
            scaledIntMemUsedValue = int(memUsedValue) * 1024
            snippet_arguments[pre_obj['proc_memUsed']].append((index, scaledIntMemUsedValue))
            snippet_arguments[pre_obj['total_memUsed']].append((index, scaledIntMemUsedValue))

        if memFreeValue:
            scaledIntMemFreeValue = int(memFreeValue) * 1024
            snippet_arguments[pre_obj['proc_memFree']].append((index, scaledIntMemFreeValue))
            snippet_arguments[pre_obj['total_memFree']].append((index, scaledIntMemFreeValue))


# Collecting data from CISCO-PROCESS-MIB
elif mib_toUse == PROCESS_cpmCPUMemoryUsed:
    default_cpu_name_structrue = '{0} ({1})'

    label_index_phycialIndexOID = {}
    for key, value in description:
        index = key.split('.')[-1]
        memFreeOid_withIndex = '{0}.{1}'.format(process_mib_oids['free'], index)
        memPhysicalIndexOid_withIndex = '{0}.{1}'.format(process_mib_oids['index'], index)

        if all_oids_response:
            memFreeValue = all_oids_response.get(memFreeOid_withIndex, None)
            memPhysicalInddexValue = all_oids_response.get(memPhysicalIndexOid_withIndex, None)
        else:
            memFreeValue = None
            memPhysicalInddexValue = None

        if value:
            scaledIntMemUsedValue = int(value) * 1024
            snippet_arguments[pre_obj['proc_memUsed']].append((index, scaledIntMemUsedValue))
            snippet_arguments[pre_obj['total_memUsed']].append((index, scaledIntMemUsedValue))

        if memFreeValue:
            scaledIntMemFreeValue = int(memFreeValue) * 1024
            snippet_arguments[pre_obj['proc_memFree']].append((index, scaledIntMemFreeValue))
            snippet_arguments[pre_obj['total_memFree']].append((index, scaledIntMemFreeValue))

        if memPhysicalInddexValue:
            label_index_phycialIndexOID[index] = '{0}.{1}'.format(process_mib_oids['label'], memPhysicalInddexValue)
        else:
            labels.append((index, default_cpu_name_structrue.format('cpu', index)))

    if len(label_index_phycialIndexOID) > 0:
        aux_label_response = {oid: val for oid, val in get_multi_with_cache(list(label_index_phycialIndexOID.values()))}

        if aux_label_response or len(aux_label_response) > 0:
            for index, oid in label_index_phycialIndexOID.items():
                label = aux_label_response.get(oid, None)
                if label:
                    labels.append((index, default_cpu_name_structrue.format(label, index)))
                else:
                    labels.append((index, default_cpu_name_structrue.format('cpu', index)))


# adding ent_physical_name_list items to snippet_arguments
for key, value in ent_physical_name_list.items():
    fill_result_handler(value)

us = snippet_arguments['Total Memory Used']
fr = snippet_arguments['Total Memory Free']

# pres_obj Total Memory Used % calculation
for idu,us in snippet_arguments['Total Memory Used']:
    for idf,fr in snippet_arguments['Total Memory Free']:
        if idu == idu:
            snippet_arguments['Total Memory Used %'].append((idu,round(us*100/(us+fr),2) if us+fr != 0 else 0))
            break


if snippet_arguments:
    print("Collections collected successfully")
    print(snmp_h.construct_Json({"1":snippet_arguments},label={"1":dict(labels)},perf_plugin=True))
else:
    print("Data not collected")
