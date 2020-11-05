-- top 15 popular src IPs
select IPv4NumToString(SrcAddr), count(*) as c from nflow group by IPv4NumToString(SrcAddr) order by c desc limit 15

-- top 15 popular dst IPs
select IPv4NumToString(DstAddr), count(*) as c from nflow group by IPv4NumToString(DstAddr) order by c desc limit 15

-- top 15 popular dst ports
select DstPort, count(*) as c from nflow group by DstPort order by c desc limit 15