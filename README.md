# Vac Module Dumper

Ferramenta para interceptar e salvar em disco os módulos carregados pelo **Valve Anti-Cheat** (VAC). O projeto utiliza hooks via [MinHook](https://github.com/TsudaKageyu/minhook) para capturar o momento em que os módulos são baixados e descriptografados pelo `steamservice.dll`.

## Compilação

O projeto foi criado originalmente para Visual Studio. Para compilar:

1. Clone este repositório incluindo o subdiretório `MinHook`.
2. Abra `VacDumper.sln` no Visual Studio 2019 ou superior.
3. Compile na configuração `Release` x86 .

Também é possível criar um projeto via **CMake** utilizando os arquivos fonte em `dllmain.cpp`, `module_utils.cpp` e `icekey.cpp`.

## Uso

Ao injetar a DLL resultante no processo do Steam, os módulos do VAC serão copiados para a pasta `C:\Lumina`. As chaves ICE utilizadas na descriptografia também são gravadas nesse diretório.

Exemplo simplificado de uso:

```cpp
// após compilar VacModuleDumper.dll
// injete a DLL no processo steam.exe ( admin )
```

O diretório de saída pode ser alterado modificando a variável `dumpPath` em `dllmain.cpp` ou passando outro caminho para `DumpVacModule`.

## Licença

Este projeto é distribuído sob a [Unlicense](LICENSE), domínio público.
