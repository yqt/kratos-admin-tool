#encoding=utf-8
import sys
import iptc
import config
from common.log import logger


class Iptables(object):

    table = iptc.Table(iptc.Table.FILTER)

    @classmethod
    def getCounterMap(cls):
        table = cls.table
        table.refresh()

        chain_in = iptc.Chain(table, 'INPUT')
        chain_out = iptc.Chain(table, 'OUTPUT')

        counter_map = {}

        for rule in chain_out.rules:
            try:
                matches = rule.matches
                if len(matches) == 2 and matches[0].name == 'tcp' and matches[1].name == 'quota':
                    port = int(matches[0].sport)
                    outbound_traffic = rule.get_counters()[1]
                    if port in counter_map:
                        counter_map[port]['outbound_traffic'] = outbound_traffic
                    else:
                        counter_map[port] = {
                            'outbound_traffic': outbound_traffic
                        }
            except Exception, e:
                logger.exception('invalid rule.')

        for rule in chain_in.rules:
            try:
                if len(rule.matches) == 1:
                    port = int(rule.matches[0].dport)
                    inbound_traffic = rule.get_counters()[1]
                    if port in counter_map:
                        counter_map[port]['inbound_traffic'] = inbound_traffic
                    else:
                        counter_map[port] = {
                            'inbound_traffic': inbound_traffic
                        }
            except Exception, e:
                logger.exception('invalid rule.')

        return counter_map

    @classmethod
    def addRule(cls, port, traffic_qouta):
        table = cls.table
        table.refresh()

        chain_in = iptc.Chain(table, 'INPUT')
        chain_out = iptc.Chain(table, 'OUTPUT')

        check_ret, check_detail = cls.checkRuleExistedByPort(port)
        if not check_ret:
            logger.error('delete existed rule failed')
            return False
        
        (in_rule_accept, out_rule_accept, out_rule_drop) = check_detail

        try:
            port = str(port)
            traffic_qouta = str(traffic_qouta)
            
            if not in_rule_accept:
                # iptables -A INPUT -p tcp --dport PORT -j ACCEPT
                rule = iptc.Rule()
                rule.protocol = 'tcp'
                match = iptc.Match(rule, 'tcp')
                match.dport = port
                rule.add_match(match)
                rule.target = iptc.Target(rule, 'ACCEPT')
                chain_in.append_rule(rule)

            if not out_rule_accept:
                # iptables -A OUTPUT -p tcp --sport PORT -m quota --quota QOUTA -j ACCEPT
                rule = iptc.Rule()
                rule.protocol = 'tcp'
                match = iptc.Match(rule, 'tcp')
                match.sport = port
                rule.add_match(match)
                match = iptc.Match(rule, 'quota')
                match.quota = traffic_qouta
                rule.add_match(match)
                rule.target = iptc.Target(rule, 'ACCEPT')
                chain_out.append_rule(rule)

            if not out_rule_drop:
                # iptables -A OUTPUT -p tcp --sport PORT -j DROP
                rule = iptc.Rule()
                rule.protocol = 'tcp'
                match = iptc.Match(rule, 'tcp')
                match.sport = port
                rule.add_match(match)
                rule.target = iptc.Target(rule, 'DROP')
                chain_out.append_rule(rule)
            
        except Exception, e:
            logger.exception('add rule failed')
            return False

        return True

    @classmethod
    def checkRuleExistedByPort(cls, port):
        table = cls.table
        table.refresh()

        chain_in = iptc.Chain(table, 'INPUT')
        chain_out = iptc.Chain(table, 'OUTPUT')

        out_rule_accept = False
        out_rule_drop = False
        in_rule_accept = False

        try:
            port = str(port)
            for rule in chain_out.rules:
                matches = rule.matches
                if len(matches) == 2 and matches[0].name == 'tcp' and matches[1].name == 'quota' \
                    and matches[0].sport == port:
                        out_rule_accept = True
                if len(matches) == 1 and matches[0].name == 'tcp' and matches[0].sport == port:
                    out_rule_drop = True

            for rule in chain_in.rules:
                matches = rule.matches
                if len(matches) == 1 and matches[0].name == 'tcp' and matches[0].dport == port:
                    in_rule_accept = True
        except Exception, e:
            logger.exception('check rule existed failed')
            return False, (in_rule_accept, out_rule_accept, out_rule_drop)

        return True, (in_rule_accept, out_rule_accept, out_rule_drop)

    @classmethod
    def deleteRule(cls, port):
        table = cls.table
        table.refresh()

        chain_in = iptc.Chain(table, 'INPUT')
        chain_out = iptc.Chain(table, 'OUTPUT')
        
        table.autocommit = False
        try:
            port = str(port)
            for rule in chain_out.rules:
                matches = rule.matches
                if len(matches) == 2 and matches[0].name == 'tcp' and matches[1].name == 'quota' \
                    and matches[0].sport == port:
                        chain_out.delete_rule(rule)
                if len(matches) == 1 and matches[0].name == 'tcp' and matches[0].sport == port:
                    chain_out.delete_rule(rule)

            for rule in chain_in.rules:
                matches = rule.matches
                if len(matches) == 1 and matches[0].name == 'tcp' and matches[0].dport == port:
                    chain_in.delete_rule(rule)
            table.commit()
            table.autocommit = True
        except Exception, e:
            logger.exception('delete rule failed')
            table.autocommit = True
            return False
        
        return True

    @classmethod
    def resetCounter(cls):
        table = cls.table
        table.refresh()
        
        chain_in = iptc.Chain(table, 'INPUT')
        chain_out = iptc.Chain(table, 'OUTPUT')
        
        try:
            table.zero_entries(chain_in)
            table.zero_entries(chain_out)
        except Exception, e:
            logger.exception('reset counter failed.')
            return False

        return True

