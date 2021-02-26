#!/usr/bin/env python3
'''Multiple classes designed for probing operations.'''

# (c) 2021 Sohum Mendon

from collections import OrderedDict
import random
import time
import textwrap

import numpy as np
from scapy.all import (
    arping,
    Ether,
    IP,
    ICMP,
    RandShort,
    sendp,
    srp
)
from scipy.stats import ttest_ind


class Field:
    '''Represents a probable field.'''

    def __init__(self, field: str):
        pass

    def modify_val(self) -> str:
        pass

    def infer_bitmask(
            self,
            rtt_0: np.ndarray,
            rtt_1: np.ndarray,
            alpha: float) -> str:
        pass


class Mac(Field):
    '''This class represents a MAC address.
    It supports operations on manipulating MAC addresses.

    It doesn't implement the infer_bitmask method, since
    MAC addresses are not bitmasked typically.
    '''

    def __init__(self, field: str):

        # store it as a 48-bit binary number
        if len(field) != 17:
            raise ValueError('MAC address should be len 17 but was len {}'
                             .format(len(field)))
        self.field = self._convert_to_bits(field)
        self.cache = OrderedDict({self.field: (-1, None)})  # keep track of previous addresses

    # various methods for constructing MAC objects
    # from a string or from a bitstring
    # also methods that allow conversion from bits
    # to a str and vice-versa
    @classmethod
    def from_bits(cls, field: int) -> Field:
        return cls(cls._convert_to_mac(field))

    @staticmethod
    def _convert_to_mac(mac: int) -> str:
        return ':'.join(textwrap.wrap('{:012x}'.format(mac), width=2))

    @staticmethod
    def _convert_to_bits(mac: str) -> int:
        return int(mac.replace(':', ''), 16)

    # shortcut methods
    def get_bits(self) -> int:
        return self._convert_to_bits(self.field)

    def get_mac(self) -> str:
        return self._convert_to_mac(self.field)

    def modify_val(
            self,
            bit: int = random.randint(0, 47),
            retry: bool = True) -> str:
        '''Flips a bit for probing.

        You can also specify precisely which bit to flip.
        retry sets whether or not we should make sure this MAC address
        is unique, according to the previous addresses that have been seen.

        Modifying a specific bit might be useful for inferring the bitmask,
        which could be extended in an IP class.
        '''

        if bit > 47 or bit < 0:
            raise ValueError('Bit invalid for MAC flipping (got: {})'
                             .format(bit))

        # could fail with Pr = 1/48
        while True:
            flipped = self.field ^ (1 << bit)

            if flipped in self.cache:
                # if there's a conflict, don't change
                if not retry:
                    return self.get_mac()

                print('MAC {} (from bit {}) already tried previously'
                      .format(self._convert_to_mac(flipped), bit))
                bit = random.randint(0, 47)
                print('Generated bit {}'.format(bit))
            else:
                break

            if not retry:
                break

        # cache which bit we flipped
        # and the previous key
        self.cache[flipped] = (bit, self.field)
        self.field = flipped

        return self.get_mac()

    def set_value(self, new_val: int = random.getrandbits(48)) -> str:
        '''Sets the value to new_val. Defaults to a random bitstring.'''
        if new_val in self.cache:
            print('MAC {} already set previously'
                  .format(new_val))
        
        # add to cache regardless

        self.cache[new_val] = (-1, self.field)
        self.field = new_val

        return self.get_mac()


class Probing:
    '''A class for methods that probe the network for configuration parameters.'''

    def __init__(self):
        self.cache = dict()

    def _get_mac(self, ip: str, force=False) -> str:
        '''Sends an ARP requests for the given IP.

        If the IP was cached recently, it won't send
        another ARP request.

        Returns an empty string if there's no reply.
        '''

        if ip in self.cache:
            return self.cache[ip]

        ans, _ = arping(ip)
        if not ans:
            return ''

        _, resp = ans[0]

        # sanity check
        if ans[0].psrc != ip:
            print('{} replied but we wanted {}'
                  .format(ans[0].psrc, ip))

        self.cache[ip] = resp.hwsrc
        return resp.hwsrc

    def _get_packet_delay(self, pkt: Ether) -> float:
        '''Sends an Ethernet frame and records the RTT.
        
        There are some issues with determining RTT in the
        library. Check the documentation:

        - https://github.com/secdev/scapy/issues/2277
        '''
        ans, unans = srp(pkt, timeout=5, verbose=0)
        if ans is None:
            return float('Inf')
        pair = ans[0]
        ping, pong = pair
        rtt = pong.time - ping.sent_time
        if rtt < 0:
            print('Invalid RTT {} obtained from {} - {}'
                  .format(rtt, pong.time, ping.sent_time))
            rtt = 0 
        return rtt

    def mac_field_probing(
            self,
            src: str = '10.0.0.1',
            dst: str = '10.0.0.3',
            n: int = 10,
            alpha: float = 0.05):
        '''Returns a string representing the guessed bitmask.

        See the paper for more information about the algorithm used.
        '''

        # generate a random MAC address
        # and compose the ethernet frame
        # use random ICMP ids to minimize chance of RTT overlap
        spoofed_src = random.getrandbits(48)
        spoofed_src = Mac.from_bits(spoofed_src)
        pkt = Ether(src=spoofed_src.get_mac())/IP(src=src, dst=dst)/ICMP(id=RandShort())

        # make arrays for the RTT
        rtt_0 = np.array([])
        rtt_1 = np.array([])

        for i in range(n):
            sendp(pkt)  # ensure the packet is inside of the flow rule

            spoofed_src.modify_val(bit=i)  # modify the ith bit
            # spoofed_src.set_value()  # randomizes the MAC address
            pkt = Ether(src=spoofed_src.get_mac())/IP(src=src, dst=dst)/ICMP(id=RandShort())

            # measure RTT
            rtt_0 = np.append(rtt_0, self._get_packet_delay(pkt))
            rtt_1 = np.append(rtt_1, self._get_packet_delay(pkt))

        # is RTT 0 > RTT 1?
        # if it is, RTT 1 triggered an installation
        p = ttest_ind(rtt_0, rtt_1, nan_policy='omit', alternative='greater').pvalue

        # return the bitmask of the field
        # for MAC addresses, this is essentially
        # true / false
        if p < alpha:
            return 'ff:ff:ff:ff:ff:ff'
        else:
            return '00:00:00:00:00:00'

    def mac_hard_timeout_probing(
            self,
            src: str = '10.0.0.1',
            dst: str = '10.0.0.3',
            bit: int = 0,
            n: int = 5,
            t_wait: float = 0.5,
            t_max: int = 60,
            alpha: float = 0.05) -> int:
        '''Returns an integer representing the probed hard timeout.

        See the paper for more information about the algorithm used.
        '''

        # make a new randomized packet
        # we know at this point that MAC addresses
        # insert new rules
        spoofed_src = random.getrandbits(48)
        spoofed_src = Mac.from_bits(spoofed_src)

        # could use spoofed_src.set_value() for randomization
        pkts = [
            Ether(src=spoofed_src.modify_val(bit=bit+i))
            / IP(src=src, dst=dst)
            / ICMP(id=RandShort())
            for i in range(n)
        ]

        # log present time and
        # send all the packets to get RTT
        t_start = time.time()
        rtt_0 = [self._get_packet_delay(pkt) for pkt in pkts]

        while True:
            time.sleep(t_wait)  # wait 0.5s
            t_end = time.time() # log the end time
            rtt_1 = [self._get_packet_delay(pkt) for pkt in pkts]

            # is RTT_0 = RTT_1?
            # if it is, we know the hard timeout
            p = ttest_ind(rtt_0, rtt_1, nan_policy='omit').pvalue

            # break loop if maximum time allotted exceeds
            # or if we discover hard timeout
            if (t_end - t_start > t_max) or (p > alpha):
                break
        
        # if we terminated due to a timeout
        # we believe the hard timeout does not exist
        if (t_end - t_start > t_max):
            return 0
        else:
            return round(t_end - t_start)

    def mac_idle_timeout_probing(
            self,
            src: str = '10.0.0.1',
            dst: str = '10.0.0.3',
            bit: int = 0,
            n: int = 5,
            t_sup: int = 500,
            alpha: float = 0.05) -> int:
        '''Returns an integer representing the probed idle timeout.

        See the paper for more information about the algorithm used.
        '''

        spoofed_src = random.getrandbits(48)
        spoofed_src = Mac.from_bits(spoofed_src)

        # could use spoofed_src.set_value() for randomization
        pkts = [
            Ether(src=spoofed_src.modify_val(bit=bit+i))
            / IP(src=src, dst=dst)
            / ICMP(id=RandShort())
            for i in range(n)
        ]

        l = 0
        r = t_sup
        while l < r:
            print('In l {} < r {} loop'.format(l, r))
            rtt_0 = [self._get_packet_delay(pkt) for pkt in pkts]
            mid = (l+r)//2
            print('Sleeping for mid = {}'.format(mid))
            time.sleep(mid)

            rtt_1 = [self._get_packet_delay(pkt) for pkt in pkts]

            # is RTT_0 = RTT_1?
            # if it is, we know the idle timeout < mid
            # else idle timeout > mid
            p = ttest_ind(rtt_0, rtt_1, nan_policy='omit').pvalue

            if p > alpha:
                r = mid - 1
            else:
                l = mid + 1

            print("Sleeping r = {} seconds".format(r))
            # if r < 0, don't sleep because it's negative
            if r >= 0:
                time.sleep(r)
            else:
                time.sleep(0)

        l = round(l)
        if l >= t_sup:
            return 0
        else:
            return l
