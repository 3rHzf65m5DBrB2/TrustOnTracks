%.out %.r1cs %.abi: %.zok
	zokrates compile -i $< -r $*.r1cs -s $*.abi -o $@ --debug

%.proving.key %.verification.key: %.out
	zokrates setup -i $*.out -v $*.verification.key -p $*.proving.key

%.witness %.wtns: %.out
	zokrates compute-witness -i $*.out -a $(WARGS) -o $*.witness --circom-witness $*.wtns

%.proof.json: %.out %.proving.key %.witness
	# zokrates compute-witness -i $*.out -a $(WARGS) -o $*.witness --circom-witness $*.wtns
	zokrates generate-proof -i $*.out -p $*.proving.key -w $*.witness -j $@

%.verifier.sol: %.verification.key
	zokrates export-verifier -i $*.verification.key -o $@

main: main.out main.proving.key main.proof.json main.verifier.sol main.verification.key
	zokrates verify -v main.verification.key -j main.proof.json

phase_lh: phase_lh.out phase_lh.proving.key phase_lh.proof.json phase_lh.verifier.sol phase_lh.verification.key
	zokrates verify -v phase_lh.verification.key -j phase_lh.proof.json

all: main
setup: main.proving.key
witness: main.witness
proof: main.proof.json

clean:
	rm -f *.out *.json *.r1cs *.key *.wtns *.witness *.abi *.sol

.PHONY: clean setup proof witness # *.witness
# .INTERMEDIATE: main.witness
