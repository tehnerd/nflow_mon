import redis
import cPickle as pickle
import json

import os



def collect_internal_traffic():
    rdb = redis.Redis()
    queue = rdb.pubsub()
    queue.subscribe('internal_traffic')
    for report in queue.listen():
        record_dict = dict()
        try:
            report = pickle.loads(report['data'])
            for record in report:
                agent = record[8]
                src = record[0]
                if agent not in record_dict:
                    record_dict[agent] = dict()
                if src not in record_dict[agent]:
                    record_dict[agent][src] = 0
                record_dict[agent][src] += int(record[6])
            min_dict = dict()
            for agent in record_dict:
                toptalkers = sorted(record_dict[agent].items(),key=lambda x:x[1])[-100:]
                min_dict[agent] = toptalkers
            rdb.set('min_toptalkers',json.dumps(min_dict))
        except Exception, e :
            continue



if __name__ == "__main__":
    pid = os.fork()
    if pid != 0:
        exit(0)
    os.setsid()
    collect_internal_traffic()
