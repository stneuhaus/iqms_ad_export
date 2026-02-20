import csv

cn_map = {}
with open('conf/group_id_mapping.csv', 'r', encoding='utf-8-sig') as f:
    reader = csv.DictReader(f)
    for row in reader:
        cn = row.get('onPremisesSamAccountName', '').strip()
        group_id = row.get('id', '').strip()
        if cn and group_id:
            cn_map[cn] = group_id

test_groups = [
    'ef.u.iqms_qms_internal_task_owner_bcc_ag_basel_ch01',
    'ef.u.iqms_qms_internal_task_owner_co_bolivia_bo01',
    'ef.u.iqms_qms_internal_task_owner_co_algeria_dz01'
]

print("Testing cache lookup:")
print("=" * 80)
for cn in test_groups:
    found = cn in cn_map
    group_id = cn_map.get(cn, 'NOT FOUND')
    print(f"CN: {cn}")
    print(f"  Found: {found}")
    print(f"  Group ID: {group_id}")
    print()

print(f"Total groups in cache with IDs: {len(cn_map)}")
