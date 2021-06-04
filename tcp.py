import asyncio
from random import randint
from tcputils import *
import os

class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)#desmonta o cabealho
        #verifica se a porta de destino é a porta qu realmente está sendo escutada
        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')# verifica o checksum e descarta
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)#informações que indentificam a concexão TCP

        if (flags & FLAGS_SYN) == FLAGS_SYN:### PASSO 1 ###
            # A flag SYN estar setada significa que é um cliente tentando estabelecer uma conexão nova
            # TODO: talvez você precise passar m ais coisas para o construtor de conexão
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao)
            conexao.seq_numero = randint(1, 0xffff)
            # conexao.seq_numero = int(os.urandom(65535))
            conexao.ack_numero = seq_no + 1
            
            flags = (FLAGS_SYN | FLAGS_ACK)
            
            temp = src_port
            src_port = dst_port
            dst_port = temp
            temp = src_addr
            src_addr = dst_addr
            dst_addr = temp

            seg = make_header(src_port, dst_port, conexao.seq_numero, conexao.ack_numero, flags)
            corrigido = fix_checksum(seg, src_addr, dst_addr)
            self.rede.enviar(corrigido, dst_addr)
            conexao.seq_numero = conexao.seq_numero + 1
            conexao.base = conexao.seq_numero
            # TODO: você precisa fazer o handshake aceitando a conexão. Escolha se você acha melhor
            # fazer aqui mesmo ou dentro da classe Conexao.

            if self.callback:
                self.callback(conexao)

        elif id_conexao in self.conexoes:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao):#passo 1 talvez mexer nos na quantidade de parametros(seq_no)
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        self.seq_numero = None
        self.ack_numero = None
        self.base = None
        self.timer = asyncio.get_event_loop().call_later(1, self._exemplo_timer)  # um timer pode ser criado assim; esta linha é só um exemplo e pode ser removida
        #self.timer.cancel()   # é possível cancelar o timer chamando esse método; esta linha é só um exemplo e pode ser removida

    def _exemplo_timer(self):
        # Esta função é só um exemplo e pode ser removida
        print('Este é um exemplo de como fazer um timer')

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        # TODO: trate aqui o recebimento de segmentos provenientes da camada de rede.
        # Chame self.callback(self, dados) para passar dados para a camada de aplicação após
        # garantir que eles não sejam duplicados e que tenham sido recebidos em ordem.
        print('recebido payload: %r' % payload)

        ### Passo 2 ###
        if seq_no != self.ack_numero:
            return
        else:
            self.callback(self,payload)

        self.ack_numero = self.ack_numero + len(payload)
        if (flags & FLAGS_FIN) == FLAGS_FIN:
            self.ack_numero += 1
            flags = FLAGS_FIN | FLAGS_ACK
        elif len(payload) <= 0:
            return
        dst_addr, dst_port, src_addr, src_port = self.id_conexao
        headerConexao = make_header(src_port, dst_port, self.seq_numero, self.ack_numero,flags)
        headerCorrigidoConexao = fix_checksum(headerConexao, src_addr, dst_addr)
        self.servidor.rede.enviar(headerCorrigidoConexao, src_addr)
    # Os métodos abaixo fazem parte da API

    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    def enviar(self, dados):
        """
        Usado pela camada de aplicação para enviar dados
        """
        # TODO: implemente aqui o envio de dados.
        # Chame self.servidor.rede.enviar(segmento, dest_addr) para enviar o segmento
        # que você construir para a camada de rede.
        ### Passo 3 ###
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        tamanho = (len(dados)/MSS)
        if tamanho < 0:
            tamanho = 1
        #print(tamanho)
        for i in range(int(tamanho)):
            #print(self.seq_numero)
            payload = dados[i*MSS:(i+1)*MSS]
            headerConexao = make_header(dst_port, src_port, self.seq_numero, self.ack_numero, FLAGS_ACK)
            headerCorrigidoConexao  = fix_checksum(headerConexao + payload, dst_addr, src_addr)
            self.servidor.rede.enviar(headerCorrigidoConexao, src_addr)
            self.seq_numero = self.seq_numero + len(payload) 

    def fechar(self):
        flag = FLAGS_FIN
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        headerConexao = make_header(dst_port, src_port, self.seq_numero, self.seq_numero, flag)
        headerCorrigidoConexao  = fix_checksum(headerConexao, dst_addr, src_addr)
        self.servidor.rede.enviar(headerCorrigidoConexao, src_addr)
        del self.servidor.conexoes[self.id_conexao]
