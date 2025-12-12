use std::f64::consts::PI;

#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Coordinates {
    pub r: f64,      // [0, 1) - radial distance in Poincaré disk
    pub theta: f64,  // [0, 2*PI) - angular position
}

impl Coordinates {
    /// Convert polar coordinates to Cartesian in complex plane
    fn to_cartesian(&self) -> (f64, f64) {
        (self.r * self.theta.cos(), self.r * self.theta.sin())
    }

    /// Hyperbolic distance formula in Poincaré disk model
    /// Formula: acosh(1 + 2|u-v|^2 / ((1-|u|^2)(1-|v|^2)))
    /// where |u|^2 = r^2 and |v|^2 = r'^2 for points in hyperbolic space
    pub fn hyperbolic_distance(&self, other: &Coordinates) -> f64 {
        let r_sq = self.r * self.r;
        let r_prime_sq = other.r * other.r;
        
        // Calculate |u - v|^2 in Cartesian coordinates
        let (x1, y1) = self.to_cartesian();
        let (x2, y2) = other.to_cartesian();
        let dx = x1 - x2;
        let dy = y1 - y2;
        let diff_sq = dx * dx + dy * dy;
        
        // Hyperbolic distance formula
        let numerator = 2.0 * diff_sq;
        let denominator = (1.0 - r_sq) * (1.0 - r_prime_sq);
        
        if denominator <= 0.0 {
            return f64::INFINITY;
        }
        
        let arg = 1.0 + numerator / denominator;
        if arg < 1.0 {
            return 0.0;
        }
        
        arg.acosh()
    }

    /// Validate that coordinates are within valid Poincaré disk bounds
    pub fn is_valid(&self) -> bool {
        self.r >= 0.0 && self.r < 1.0 && self.theta >= 0.0 && self.theta <= 2.0 * PI
    }

    /// Normalize theta to [0, 2*PI)
    pub fn normalize(&mut self) {
        const TWO_PI: f64 = 2.0 * PI;
        self.theta = self.theta.rem_euclid(TWO_PI);
    }
}

/// Find the neighbor with the minimum hyperbolic distance to the target
pub fn find_greedy_hop<T: Copy>(target: Coordinates, neighbors: Vec<(T, Coordinates)>) -> Option<T> {
    if neighbors.is_empty() {
        return None;
    }
    
    neighbors
        .into_iter()
        .min_by(|(_, c1), (_, c2)| {
            let d1 = c1.hyperbolic_distance(&target);
            let d2 = c2.hyperbolic_distance(&target);
            d1.partial_cmp(&d2).unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|(id, _)| id)
}
