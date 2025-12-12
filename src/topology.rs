use num_complex::Complex;
use std::f64::consts::PI;

#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Coordinates {
    pub r: f64,      // [0, 1)
    pub theta: f64,  // [0, 2*PI)
}

impl Coordinates {
    pub fn to_point(&self) -> Complex<f64> {
        Complex::from_polar(&self.r, &self.theta)
    }

    pub fn hyperbolic_distance(&self, other: &Coordinates) -> f64 {
        let u = self.to_point();
        let v = other.to_point();
        let norm_u = u.norm_sqr();
        let norm_v = v.norm_sqr();
        let diff = (u - v).norm_sqr();
        let arg = 1.0 + 2.0 * diff / ((1.0 - norm_u) * (1.0 - norm_v));
        arg.acosh()
    }
}

/// Find the neighbor with the minimum hyperbolic distance to the target
pub fn find_greedy_hop<T: Copy>(target: Coordinates, neighbors: Vec<(T, Coordinates)>) -> Option<T> {
    neighbors
        .into_iter()
        .min_by(|(_, c1), (_, c2)| {
            let d1 = c1.hyperbolic_distance(&target);
            let d2 = c2.hyperbolic_distance(&target);
            d1.partial_cmp(&d2).unwrap()
        })
        .map(|(id, _)| id)
}
