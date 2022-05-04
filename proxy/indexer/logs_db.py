import json

from ..indexer.base_db import BaseDB


class LogsDB(BaseDB):
    def __init__(self):
        BaseDB.__init__(self, 'neon_transaction_logs')

    def push_logs(self, logs, block):
        rows = []
        for log in logs:
            for topic in log['topics']:
                rows.append(
                    (
                        log['address'],
                        block.hash,
                        block.slot,
                        log['transactionHash'],
                        int(log['transactionLogIndex'], 16),
                        topic,
                        json.dumps(log)
                    )
                )
        if len(rows):
            # logger.debug(rows)
            cur = self._conn.cursor()
            cur.executemany(f'''
                            INSERT INTO {self._table_name}(address, blockHash, blockNumber,
                                            transactionHash, transactionLogIndex, topic, json)
                            VALUES (%s, %s, %s,  %s, %s,  %s, %s) ON CONFLICT DO NOTHING''', rows)


    def get_logs(self, fromBlock = None, toBlock = None, addresses = [], topics = [], blockHash = None):
        queries = []
        params = []

        if fromBlock is not None:
            queries.append("blockNumber >= %s")
            params.append(fromBlock)

        if toBlock is not None:
            queries.append("blockNumber <= %s")
            params.append(toBlock)

        if blockHash is not None:
            blockHash = blockHash.lower()
            queries.append("blockHash = %s")
            params.append(blockHash)

        if len(topics) > 0:
            query_placeholder = ", ".join(["%s" for _ in range(len(topics))])
            topics_query = f"topic IN ({query_placeholder})"

            queries.append(topics_query)
            params += topics

        if len(addresses) > 0:
            query_placeholder = ", ".join(["%s" for _ in range(len(addresses))])
            address_query = f"address IN ({query_placeholder})"

            queries.append(address_query)
            params += addresses

        query_string = f"SELECT * FROM {self._table_name}"
        if len(queries):
            query_string += " WHERE "
            for idx, query in enumerate(queries):
                query_string += query
                if idx < len(queries) - 1:
                    query_string += " AND "

        query_string += " ORDER BY blockNumber desc LIMIT 1000"

        self.debug(query_string)
        self.debug(params)

        with self._conn.cursor() as cursor:
            cursor.execute(query_string, tuple(params))
            rows = cursor.fetchall()

        logs = set([row[-1] for row in rows])
        return [json.loads(log) for log in logs]
