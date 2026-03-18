use nalgebra::Vector3;
use std::time::SystemTime;

/// Represents a point in 3D Phase Space derived from sequential nonces.
/// In a truly random system, these points should be uniformly distributed.
/// In a system with a flawed PRNG, they may cluster on a "Strange Attractor" (like Lorenz).
pub struct PhaseSpacePoint {
    pub coords: Vector3<f64>,
    pub timestamp: u64,
}

pub struct ChaosAnalyzer {
    pub sigma: f64, // Lorenz parameter (Prandtl number)
    pub rho: f64,   // Lorenz parameter (Rayleigh number)
    pub beta: f64,  // Lorenz parameter (Physical dimensions)
}

impl ChaosAnalyzer {
    pub fn new_lorenz_standard() -> Self {
        Self {
            sigma: 10.0,
            rho: 28.0,
            beta: 8.0 / 3.0,
        }
    }

    /// Maps three sequential 256-bit nonces (k1, k2, k3) into a normalized 3D coordinate.
    /// We normalize the 256-bit integers to the range [0.0, 100.0] for the Lorenz manifold.
    pub fn map_nonces_to_space(k1: &[u8; 32], k2: &[u8; 32], k3: &[u8; 32]) -> PhaseSpacePoint {
        let x = u256_to_f64(k1) % 100.0;
        let y = u256_to_f64(k2) % 100.0;
        let z = u256_to_f64(k3) % 100.0;

        PhaseSpacePoint {
            coords: Vector3::new(x, y, z),
            timestamp: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
        }
    }

    /// Calculates the "Correlation Dimension" to see if the points belong to a 
    /// low-dimensional manifold (the "Butterfly" effect) rather than 3D noise.
    pub fn calculate_fractal_dimension(&self, points: &[PhaseSpacePoint]) -> f64 {
        if points.len() < 2 {
            return 3.0; // Assume 3D noise if not enough points
        }
        
        // Simplified Grassberger-Procaccia algorithm approximation for demonstration
        let mut close_pairs = 0;
        let mut total_pairs = 0;
        let r = 15.0; // Distance threshold
        
        for i in 0..points.len() {
            for j in (i + 1)..points.len() {
                let dist = (points[i].coords - points[j].coords).norm();
                if dist < r {
                    close_pairs += 1;
                }
                total_pairs += 1;
            }
        }
        
        if total_pairs == 0 || close_pairs == 0 {
            return 3.0;
        }

        let c_r = close_pairs as f64 / total_pairs as f64;
        let dim = c_r.ln() / r.ln(); // Roughly approximating Correlation Dimension

        // Lorenz attractor is typically ~2.06. 
        // A truly random 3D space would have a higher dimension closer to 3.0, 
        // though our simple approx might scale differently.
        dim.abs()
    }
}

pub fn u256_to_f64(bytes: &[u8; 32]) -> f64 {
    // Converts the first 8 bytes of the nonce to a float for mapping
    let mut b = [0u8; 8];
    b.copy_from_slice(&bytes[0..8]);
    u64::from_be_bytes(b) as f64
}
