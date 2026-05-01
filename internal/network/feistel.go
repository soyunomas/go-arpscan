// internal/network/feistel.go
//
// Generador pseudoaleatorio O(1) sin estado para recorrer un rango [0, 2^k)
// de IPs en orden permutado, sin almacenar el orden en memoria.
//
// *[Regla 79]* — En lugar de hacer rand.Shuffle sobre un []uint32 (que cuesta
// O(N) en RAM y destroza la cache al recorrerlo), aplicamos un Feistel cipher
// de 4 rondas sobre un índice secuencial i. La salida es una permutación
// determinista del rango [0, 2^bits), reversible y con distribución uniforme.
//
// Coste: 4 multiplicaciones + 4 XORs por IP. Cero asignaciones, cero memoria.
// Determinismo: misma seed → misma permutación (compatible con --randomseed).
//
// Uso típico:
//
//	f := NewFeistel(uint32(seed), 16) // /16 = 65 536 IPs
//	for i := uint32(0); i < f.Size(); i++ {
//	    offset := f.Encrypt(i)        // pseudoaleatorio en [0, 2^16)
//	    ip := baseIPBE + offset       // o como construyas tu IP
//	}
package network

// Feistel cifra/descifra valores en [0, 2^bits) con una permutación
// pseudoaleatoria parametrizada por una seed.
//
// Para soportar tamaños de subred no-potencia-de-2 (e.g. /23 = 512 IPs cabe
// en 9 bits, pero un /22.5 no), siempre redondeamos bits al siguiente entero
// y usamos "cycle walking": si el valor cae fuera del tamaño real, lo volvemos
// a cifrar hasta que entre. En la práctica, para CIDRs estándar (/8../32) bits
// es exacto y el cycle walking nunca se activa.
type Feistel struct {
	keys [4]uint32 // sub-claves derivadas
	half uint8     // bits por mitad
	mask uint32    // máscara de la mitad ((1<<half)-1)
	size uint32    // 2^bits, o 0 si bits==32
	full uint8     // total de bits útiles
}

// NewFeistel crea un Feistel para un espacio de 2^bits valores.
// bits ∈ [1, 32]. Para escaneos típicos: /24→8, /16→16, /8→24.
//
//go:nosplit
func NewFeistel(seed uint32, bits uint8) Feistel {
	if bits == 0 {
		bits = 1
	}
	if bits > 32 {
		bits = 32
	}
	half := (bits + 1) >> 1 // ceil(bits/2)
	mask := uint32((uint64(1) << half) - 1)
	var size uint32
	if bits < 32 {
		size = uint32(1) << bits
	} // bits==32 → size=0 (interpreta como "todo el espacio")

	// Sub-claves derivadas con un splitmix simple. Cada ronda usa una
	// constante distinta para descorrelacionar las rondas.
	const c0, c1, c2, c3 uint32 = 0x9E3779B1, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A
	return Feistel{
		keys: [4]uint32{
			mix32(seed ^ c0),
			mix32(seed ^ c1),
			mix32(seed ^ c2),
			mix32(seed ^ c3),
		},
		half: half,
		mask: mask,
		size: size,
		full: bits,
	}
}

// Size devuelve el número total de valores únicos que produce (2^bits).
// Devuelve 0 cuando bits==32 (interprétese como 2^32).
//
//go:nosplit
func (f Feistel) Size() uint32 { return f.size }

// Encrypt aplica la permutación al índice i ∈ [0, Size()) y devuelve un valor
// en [0, Size()) sin colisiones.
//
//go:nosplit
func (f Feistel) Encrypt(i uint32) uint32 {
	// Truncamos i al espacio
	if f.size != 0 {
		i &= f.size - 1
	}
	l := (i >> f.half) & f.mask
	r := i & f.mask
	// 4 rondas Feistel
	for k := 0; k < 4; k++ {
		l, r = r, l^(round(r, f.keys[k])&f.mask)
	}
	out := (l << f.half) | r
	if f.size != 0 {
		out &= f.size - 1
	}
	return out
}

// round es la función no-lineal F(r, k). Usamos un mix multiplicativo barato
// que el compilador inlinea y que ejerce los registros de la CPU sin tocar
// memoria (cero allocs, cache-friendly).
//
//go:nosplit
func round(r, k uint32) uint32 {
	x := r ^ k
	x ^= x >> 16
	x *= 0x85EBCA6B
	x ^= x >> 13
	x *= 0xC2B2AE35
	x ^= x >> 16
	return x
}

//go:nosplit
func mix32(x uint32) uint32 {
	x ^= x >> 16
	x *= 0x7FEB352D
	x ^= x >> 15
	x *= 0x846CA68B
	x ^= x >> 16
	return x
}
