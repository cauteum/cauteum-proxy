package proxy

import "testing"

func TestWSFragmentBufferReconstructsLogicalMessage(t *testing.T) {
	var fragments wsFragmentBuffer
	if _, ready, err := fragments.accept(wsFrame{Opcode: wsOpcodeText, Payload: []byte("hel"), Fin: false}); err != nil || ready {
		t.Fatalf("first fragment ready=%v err=%v", ready, err)
	}
	if got, ready, err := fragments.accept(wsFrame{Opcode: wsOpcodeContinuation, Payload: []byte("lo"), Fin: true}); err != nil || !ready || got.Opcode != wsOpcodeText || string(got.Payload) != "hello" || !got.Fin {
		t.Fatalf("final fragment=%+v ready=%v err=%v", got, ready, err)
	}
}

func TestWSFragmentBufferPassesControlFramesDuringFragment(t *testing.T) {
	var fragments wsFragmentBuffer
	_, _, _ = fragments.accept(wsFrame{Opcode: wsOpcodeBinary, Payload: []byte{1}, Fin: false})
	got, ready, err := fragments.accept(wsFrame{Opcode: wsOpcodePing, Payload: []byte("ping"), Fin: true})
	if err != nil || !ready || got.Opcode != wsOpcodePing || string(got.Payload) != "ping" {
		t.Fatalf("control frame=%+v ready=%v err=%v", got, ready, err)
	}
	got, ready, err = fragments.accept(wsFrame{Opcode: wsOpcodeContinuation, Payload: []byte{2}, Fin: true})
	if err != nil || !ready || got.Opcode != wsOpcodeBinary || len(got.Payload) != 2 {
		t.Fatalf("binary final=%+v ready=%v err=%v", got, ready, err)
	}
}

func TestWSFragmentBufferRejectsInvalidSequenceAndOversize(t *testing.T) {
	var fragments wsFragmentBuffer
	if _, _, err := fragments.accept(wsFrame{Opcode: wsOpcodeContinuation, Fin: true}); err == nil {
		t.Fatal("continuation without start was accepted")
	}
	if _, _, err := fragments.accept(wsFrame{Opcode: wsOpcodeText, Payload: make([]byte, maxWSMessageBytes+1), Fin: true}); err == nil {
		t.Fatal("oversized message was accepted")
	}
	if _, _, err := fragments.accept(wsFrame{Opcode: wsOpcodePing, Payload: make([]byte, 126), Fin: true}); err == nil {
		t.Fatal("oversized control frame was accepted")
	}
	if _, _, err := fragments.accept(wsFrame{Opcode: wsOpcodePing, Fin: false}); err == nil {
		t.Fatal("fragmented control frame was accepted")
	}
}
