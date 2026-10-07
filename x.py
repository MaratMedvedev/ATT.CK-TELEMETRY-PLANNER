import json
with open('./data/generated/telemetry_records.json') as f:
    log_source = json.load(f)
    a = {}
    print(len(log_source))
    for i in range(len(log_source)):
        l = log_source[i]['log_source']
        a[l] = a.get(l, 0) + 1
    its = sorted(list(zip(a.keys(), a.values())), key=lambda x: x[1], reverse=True)
    # print(its)
    print(len(its))
    import yaml

# Open your YAML file and load its contents
with open('./data/generated/techniques_scraped.yml', 'r') as file:
    config = yaml.safe_load(file)
    a={}
    print(len(config['techniques']))
    for i in range(len(config['techniques'])):
        t = config['techniques'][i]['sources']
        for j in range(len(t)):
            l = t[j]['raw_log_source']
            a[l] = a.get(l, 0) + 1
    #print(a)