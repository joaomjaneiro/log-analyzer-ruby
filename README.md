# log-analyzer-ruby
# Analisador de Logs em Ruby  Script simples em Ruby para contar o número de acessos por IP a partir de um ficheiro de log (formato comum Apache/Nginx).  
💡 Projeto de aprendizagem no contexto da formação em Cibersegurança (IEFP). 
## Exemplo de logs

10.200.1.254	Feb  7 13:11:19	TheFirewall.scorpionsphere.pt	user	notice	configd.py[8742]	[033a412a-f883-4950-b8c4-e0270c7863a5] request filter log output 
10.200.1.254	Feb  7 13:11:20	TheFirewall.scorpionsphere.pt	local0	info	filterlog[36443]	11,,,02f4bab031b57d1e30553ce08e0ec131,re0,match,block,in,4,0x0,,128,30803,0,none,17,udp,329,0.0.0.0,255.255.255.255,68,67,309 
10.200.1.254	Feb  7 13:11:20	TheFirewall.scorpionsphere.pt	local0	info	filterlog[36443]	72,,,d11e26d2e888cfd7d23089d2f57e9958,ale0,match,pass,out,4,0x0,,63,30654,0,DF,6,tcp,60,192.168.230.250,34.107.165.5,55823,443,0,S,4290238999,,65535,,mss;sackOK;TS;nop;wscale 
10.200.1.254	Feb  7 13:11:20	TheFirewall.scorpionsphere.pt	local0	info	filterlog[36443]	81,,,6bd208bf217ff031903b494caa219cec,re0,match,pass,in,4,0x0,,128,45359,0,none,17,udp,96,10.200.1.101,8.8.8.8,51743,53,76 
10.200.1.254	Feb  7 13:11:20	TheFirewall.scorpionsphere.pt	local0	info	filterlog[36443]	72,,,d11e26d2e888cfd7d23089d2f57e9958,ale0,match,pass,out,4,0x0,,127,45359,0,none,17,udp,96,192.168.230.250,8.8.8.8,14682,53,76 
10.200.1.254	Feb  7 13:11:21	TheFirewall.scorpionsphere.pt	local0	info	filterlog[36443]	81,,,6bd208bf217ff031903b494caa219cec,re0,match,pass,in,4,0x0,,128,45360,0,none,17,udp,84,10.200.1.101,8.8.8.8,62926,53,64 
10.200.1.254	Feb  7 13:11:21	TheFirewall.scorpionsphere.pt	local0	info	filterlog[36443]	72,,,d11e26d2e888cfd7d23089d2f57e9958,ale0,match,pass,out,4,0x0,,127,45360,0,none,17,udp,84,192.168.230.250,8.8.8.8,1465,53,64 
10.200.1.254	Feb  7 13:11:21	TheFirewall.scorpionsphere.pt	local0	info	filterlog[36443]	81,,,6bd208bf217ff031903b494caa219cec,re0,match,pass,in,4,0x0,,128,45361,0,none,17,udp,126,10.200.1.101,8.8.8.8,50032,53,106 
10.200.1.254	Feb  7 13:11:21	TheFirewall.scorpionsphere.pt	local0	info	filterlog[36443]	72,,,d11e26d2e888cfd7d23089d2f57e9958,ale0,match,pass,out,4,0x0,,127,45361,0,none,17,udp,126,192.168.230.250,8.8.8.8,14947,53,106 

Script em ruby
system ("cls")
dados = File.open("syslog")

total_filterlog = 0
dns = 0
http = 0
vpn = 0

ips_http = []

tcp_http = 0
udp_http = 0

id_vpn = "10.1.10"

dados.each do |linha|

if linha.include?("<PACKET_LOG>:")
 

  partes_data = linha.split (" ")
  mes = partes_data[1]
  dia = partes_data[2]
  
  packetlog = linha.split("<PACKET_LOG>:").last.strip
  partes = packetlog.split (",")
  
if partes.length > 16
  sid1 = partes[0]
  sid2 = partes[1]
  iporigemvpn = partes[8]
  ipdestinovpn = partes[10]
  iprealorigem = partes[16]
  iprealdestino = partes[17]
 
 
  puts "Data: #{mes} #{dia}"
  puts "SID 1: #{sid1}"
  puts "SID 2: #{sid2}"
  puts "VPN origem: #{iporigemvpn}"
  puts "VPN destino: #{ipdestinovpn}"
  puts "IP real origem: #{iprealorigem}"
  puts "IP real destino: #{iprealdestino}"
  puts "-" *30

end
end

colunas = linha.split("\t")

colunas.each do |coluna|


end
 
if colunas.length > 6

servico=colunas[5] 

    if servico.include?("filterlog")
total_filterlog = total_filterlog + 1

mensagem = colunas[6]

partes = mensagem.split(",")



if partes.length > 21

protocolo = partes[16].strip.downcase
ip_origem = partes[18]
ip_destino = partes[19]
porta_destino = partes [21].strip
porta_origem = partes [20]



if porta_destino == "53"
dns = dns + 1
end

if porta_destino == "80" or porta_destino =="443" 
http = http + 1
ips_http.push(ip_destino)



if protocolo == "tcp"
tcp_http += 1
end

if protocolo == "udp"
udp_http += 1
end
end

if porta_destino == "5555"

vpn += 1
end

 end
 end
 end
 end
 
 puts "TOTAL de pacotes filterlog: " + total_filterlog.to_s
puts "Pacotes DNS (porta 53): " + dns.to_s
puts "Pacotes HTTP\HTTPS (porta 80 e porta 443): " + http.to_s
puts "Pacotes VPN (porta 5555): " + vpn.to_s



if http > 0
  perc_tcp = (tcp_http * 100) /http
  perc_udp = (udp_http * 100) / http

  puts
  puts "Percentagem de uso TCP em HTTP/HTTPS: " + perc_tcp.to_s + "%"
  puts "Percentagem de uso UDP em HTTP/HTTPS: " + perc_udp.to_s + "%"
end
