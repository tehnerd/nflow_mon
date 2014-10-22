import redis
import cPickle as pickle
import json
from string import join

import os



def collect_internal_traffic():
    rdb = redis.Redis()
    queue = rdb.pubsub()
    queue.subscribe('internal_traffic')
    for report in queue.listen():
        record_dict = dict()
        intf_record_dict = dict()
        try:
            report = pickle.loads(report['data'])
            for record in report:
                agent = record[8]
                src = record[0]
                print(record)
                dst = record[1]
                intf = record[5]
                if agent not in record_dict:
                    record_dict[agent] = dict()
                    intf_record_dict[agent] = dict()
                if intf not in intf_record_dict[agent]:
                    intf_record_dict[agent][intf] = dict()
                if src not in record_dict[agent]:
                    record_dict[agent][src] = 0
                if src not in intf_record_dict[agent][intf]:
                    intf_record_dict[agent][intf][src] = 0
                record_dict[agent][src] += int(record[6])
                intf_record_dict[agent][intf][src] += int(record[6])
            min_dict = dict()
            min_dict_intf = dict()
            for agent in record_dict:
                toptalkers = sorted(record_dict[agent].items(),key=lambda x:x[1])[-100:]
                min_dict[agent] = toptalkers
            for agent in intf_record_dict:
                if agent not in min_dict_intf:
                    min_dict_intf[agent] = dict()
                for intf in intf_record_dict[agent]:
                    toptalkers = sorted(intf_record_dict[agent][intf].items(),
                                            key=lambda x:x[1])[-100:]
                    min_dict_intf[agent][intf] = toptalkers
                
            rdb.set('min_toptalkers',json.dumps(min_dict))
            rdb.set('min_toptalkers_intf',json.dumps(min_dict_intf))
        except Exception, e :
            continue



if __name__ == "__main__":
    pid = os.fork()
    if pid != 0:
        exit(0)
    os.setsid()
    collect_internal_traffic()
