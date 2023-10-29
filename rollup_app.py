from opensearchpy import OpenSearch
from dotenv import dotenv_values
import pandas as pd
import yaml
import os
import requests
import urllib3
import time
import json

def post_data(creds, params, data_agg):
  with OpenSearch(hosts = [{'host': creds['WI_HOST'], 'port': 9200}],
    http_compress = True, http_auth = (creds['WI_USER'], creds['WI_PASS']),
    use_ssl = True, verify_certs = False, ssl_show_warn = False) as client:
    aux_control=1
    data2bulk=""
    now=time.strftime("%Y.%m.%d", time.localtime())
    for event in data_agg:
      index_header = { "index" : { "_index": f"wazuh-agg-{now}" } }
      event['tag'] = params['add_tag']
      event.update(params['set_col'])
      data2index = f"\n{json.dumps(index_header)}\n{json.dumps(event)}"
      data2bulk+=data2index
      if aux_control % 5 == 0:
        client.bulk(data2bulk)
        data2bulk=""
        time.sleep(1)
      aux_control+=1

def agg_data(data_json, cfg_name, params):
  df = pd.json_normalize(data_json, max_level=10)
  df.drop(columns=["_index", "_id", "_score"], inplace=True)
  df.columns = [col[8::] for col in df.columns]
  df['@timestamp'] = pd.to_datetime(df['@timestamp'], utc=True)
  df['@timestamp'] = df['@timestamp'].dt.floor(f"{params['dt_hist']}T")
  df.fillna('NA', inplace=True)
  df = df.groupby(params['fields']).size().reset_index(name="count")
  df['@timestamp'] = df['@timestamp'].dt.strftime("%Y-%m-%dT%H:%M:%S")
  df.columns = [c.replace(".", "_") for c in df.columns]
  return  df.to_dict(orient='records')

def get_data(creds, params):
  db_docs_limit=500000 # set docs limit
  requests.put(f"https://{creds['WI_HOST']}:9200/{params['index_pattern']}/_settings",
    auth=requests.auth.HTTPBasicAuth(creds['WI_USER'], creds['WI_PASS']), verify=False,
    json={"index":{"max_result_window":db_docs_limit}})
  with OpenSearch(hosts = [{'host': creds['WI_HOST'], 'port': 9200}],
    http_compress = True, http_auth = (creds['WI_USER'], creds['WI_PASS']),
    use_ssl = True, verify_certs = False, ssl_show_warn = False) as client:
    query = {
      "size": db_docs_limit,
      "_source": { "includes": params['fields'] },
      "query": {
        "bool": {
          "filter": [
            { "range": { "@timestamp": { "lte": f"now/d-{params['until_ndays_ago']}d" } } }
            #{ "query_string": { "query": params['query'] } }
          ]
        }
      }
    }
    response = client.search(index=params['index_pattern'], body=query)['hits']['hits']
    return response

def main(configs="rollup.yml"):
  app_dir = os.path.dirname(os.path.realpath(__file__))
  creds = dotenv_values(f"{app_dir}/.env")
  with open(f"{app_dir}/config/{configs}", "r") as yamlfile:
    confs = yaml.safe_load(yamlfile)
  for cfg_name, params in confs.items():
    data_json = get_data(creds, params)
    if len(data_json):
      data_agg = agg_data(data_json, cfg_name, params)
      post_data(creds, params, data_agg)

if __name__=="__main__":
  urllib3.disable_warnings()
  main()