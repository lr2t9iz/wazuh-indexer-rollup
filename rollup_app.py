from opensearchpy import OpenSearch
from dotenv import dotenv_values
import pandas as pd
import yaml
import os

def agg_data(data_json):
  df = pd.json_normalize(data_json, max_level=10)
  df.drop(columns=["_index", "_id", "_score"], inplace=True)
  aux_col = [col[8::] for col in df.columns]
  df.columns=aux_col
  return df

def get_data(creds, params):
  with OpenSearch(hosts = [{'host': creds['WI_HOST'], 'port': 9200}],
    http_compress = True, http_auth = (creds['WI_USER'], creds['WI_PASS']),
    use_ssl = True, verify_certs = False, ssl_show_warn = False) as client:
    query = {
      "size": 10,
      "_source": ["agent.name", "rule.id"],
      "query": {
        "bool": {
          "filter": [
            { "range": { "@timestamp": { "gt": params['since_date'], "lte": "now/m" } } }
            #{ "query_string": { "query": cfg_report['query'] } }
          ]
        }
      }
    }
    response = client.search(index=params['index_pattern'], body=query)['hits']['hits']
    return response

def main(configs="rollup.yml"):
  app_dir = os.path.dirname(os.path.realpath(__file__))
  creds = dotenv_values(f"{app_dir}/../.env")
  with open(f"{app_dir}/config/{configs}", "r") as yamlfile:
    confs = yaml.safe_load(yamlfile)
  for cfg_name, params in confs.items():
    data_json = get_data(creds, params)
    print(cfg_name, params)
    if len(data_json):
      data_agg = agg_data(data_json)
      print(data_agg)

if __name__=="__main__":
  main()