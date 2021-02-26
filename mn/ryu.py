'''This class interacts with Ryu's REST API.

It helps with the data collection expected for
evaluating whether the switches have their flow tables
overfilled.

(c) 2021 Sohum Mendon
'''

from typing import (
    Any,
    Dict,
    List,
    Optional,
    Tuple,
)
import requests


class RyuAPI:
    '''A class for interacting with Ryu's REST API.

    This should not be used in experimentation, since
    the attacker should not have knowledge of the network
    configuration.

    This expects OpenFlow v1.4 for certain methods.
    '''

    def __init__(self, url: str):
        '''Alows querying the Ryu API when provided the hostname.

        e.g. url = 192.168.1.155:8080, or 127.0.0.1:8080
        REST API documentation:
            https://ryu.readthedocs.io/en/latest/app/ofctl_rest.html

        Only works if ryu.app.ofctl_rest is included.
        '''

        self.url = url

    def _assemble_url(self, args: List[str]) -> str:
        '''Creates a URL for the REST API calls.

        Expects a list of parameters that come
        after the base url. They are joined with /.
        '''

        return 'http://' + self.url + '/' + \
               '/'.join(args)

    def _handle_error_status(self, code: int, url: str) -> bool:
        if code != 200:
            print('Error fetching {} response'.format(url))
            return True
        return False

    def aggregate_flow_stats(self, dpid: int) -> Optional[Dict[str, Any]]:
        '''A wrapper for the API call.

        See:
            https://ryu.readthedocs.io/en/latest/app/ofctl_rest.html#get-aggregate-flow-stats
        '''

        url = self._assemble_url(['stats', 'aggregateflow', str(dpid)])

        resp = requests.get(url)
        if self._handle_error_status(resp.status_code, url):
            return

        return resp.json()

    def get_num_flows(self, switches: Tuple[int] = (4, 5)) -> int:
        '''Gets the total number of flows over the two switches.

        Expects an iterable of numbers that correspond to
        the switch id numbers. By default, it's set to the switch's
        id numbers in the experiment.

        Note that this may return double the number of actual flows,
        since the flow rule may be installed on both the first switch
        and the second switch.
        '''

        count = 0
        for switch_id in switches:
            restful_json = self.aggregate_flow_stats(switch_id)
            if restful_json is None:
                continue

            count += restful_json[str(switch_id)][0]['flow_count']

        return count

    def get_flow_stats(self, dpid: int) -> Optional[Dict[str, Any]]:
        '''A wrapper for the API call.

        See:
            https://ryu.readthedocs.io/en/latest/app/ofctl_rest.html#get-all-flows-stats
        '''

        url = self._assemble_url(['stats', 'flow', str(dpid)])

        resp = requests.get(url)
        if self._handle_error_status(resp.status_code, url):
            return

        return resp.json()
