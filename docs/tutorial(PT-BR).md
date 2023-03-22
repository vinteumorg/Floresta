## Tutorial
### Introdução:
Este programa é uma pequena implementação de node com um Electrum Server acoplado. Ela se comporta semelhante a um setup com Bitcoin Core + Electrum Personal Server, porém com algumas diferenças chave.  

- Node e Electrum Server estão no mesmo binário, tornando o processo mais simples e com menos erros.
- O full node utiliza uma tecnologia nova chamada `Utreexo` para reduzir o consumo de recursos, você consegue rodar o node com menos de 1GB de disco e RAM.
- Diferentemente do EPS, esse Electrum Server suporta múltiplas conexões simultâneas.

### Utilizando
Existem duas maneiras de se obter o executável. Você pode compilar do código-fonte ou baixar o binário pré compilado do Github. Para intruções de como compilar o código-fonte, veja abaixo.

### Compilando

Para compilar, você precisa da toochain do Rust e o Cargo, mais informações [aqui](https://www.rust-lang.org/).
Você pode obter o código-fonte baixando do Github ou clonando com
```bash
git clone https://www.github.com/Davidson-Souza/floresta
```
Navegue para dentro da pasta com
```bash
cd floresta
```

compile com:
```bash
cargo bild --release
```
se tudo estiver ok, ele irá mostrar uma tela de ajuda com os comandos e opções do programa.

### Preparação
Antes de rodar ele pela primeira vez, você precisa extrair a xpub da sua carteira. Na Electrum, basta ir no menu "Carteira" e clicar em "Informações", a xpub vai aparecer em uma caixa de texto grande.

Uma vez que você tenha a Chave Pública Extendida em mãos, basta inicializar o servidor com ela, utilizando o comando abaixo.
```bash
floresta -c config.toml --network  signet run
```
Onde:
- `network` é a rede que você está utilizando, bitcoin significa mainnet, outros valores válidos são signet, regtest e testnet. Todas são redes de teste que são funcionalmente idênticas a rede principal (mainnet), porém utilizada apenas para teste, e suas moedas não tem valor algum.
