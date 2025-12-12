// Unit tests for topology coordinate validation and safety

use crate::topology::Coordinates;
use std::f64::consts::PI;

#[test]
fn test_coordinate_validation_valid_cases() {
    // Test valid coordinates
    let valid_coords = vec![
        Coordinates { r: 0.0, theta: 0.0 },
        Coordinates { r: 0.5, theta: PI },
        Coordinates { r: 0.99, theta: 2.0 * PI - 0.01 },
        Coordinates { r: 0.0001, theta: 0.0001 },
    ];
    
    for coord in valid_coords {
        assert!(coord.is_valid(), "Coordinate should be valid: r={}, theta={}", coord.r, coord.theta);
    }
}

#[test]
fn test_coordinate_validation_invalid_r() {
    // Test that r outside [0, 1) is invalid
    let invalid_r = vec![
        Coordinates { r: -0.1, theta: 0.0 },
        Coordinates { r: 1.0, theta: 0.0 },
        Coordinates { r: 1.5, theta: PI },
        Coordinates { r: f64::INFINITY, theta: 0.0 },
        Coordinates { r: f64::NAN, theta: 0.0 },
    ];
    
    for coord in invalid_r {
        assert!(!coord.is_valid(), "Coordinate should be invalid: r={}, theta={}", coord.r, coord.theta);
    }
}

#[test]
fn test_coordinate_validation_invalid_theta() {
    // Test that theta outside [0, 2*PI] is invalid
    let invalid_theta = vec![
        Coordinates { r: 0.5, theta: -0.1 },
        Coordinates { r: 0.5, theta: 2.0 * PI + 0.1 },
        Coordinates { r: 0.5, theta: 999.0 },
        Coordinates { r: 0.5, theta: f64::INFINITY },
        Coordinates { r: 0.5, theta: f64::NAN },
    ];
    
    for coord in invalid_theta {
        assert!(!coord.is_valid(), "Coordinate should be invalid: r={}, theta={}", coord.r, coord.theta);
    }
}

#[test]
fn test_hyperbolic_distance_boundary_case() {
    // Test that coordinates at r=1.0 return INFINITY
    let boundary = Coordinates { r: 1.0, theta: 0.0 };
    let normal = Coordinates { r: 0.5, theta: 0.0 };
    
    let dist = boundary.hyperbolic_distance(&normal);
    assert!(dist.is_infinite(), "Distance to boundary point should be infinite");
}

#[test]
fn test_hyperbolic_distance_denominator_zero() {
    // Test that r values very close to 1.0 are handled safely
    let near_boundary = Coordinates { r: 0.9999999, theta: 0.0 };
    let other = Coordinates { r: 0.5, theta: 0.0 };
    
    let dist = near_boundary.hyperbolic_distance(&other);
    // Should return a large but finite value, or INFINITY if denominator <= 0
    assert!(dist.is_finite() || dist.is_infinite(), "Distance should be well-defined");
    assert!(dist >= 0.0, "Distance should be non-negative");
}

#[test]
fn test_hyperbolic_distance_same_point() {
    // Distance from point to itself should be 0
    let coord = Coordinates { r: 0.7, theta: PI / 4.0 };
    let dist = coord.hyperbolic_distance(&coord);
    assert!(dist.abs() < 1e-10, "Distance to self should be ~0, got {}", dist);
}

#[test]
fn test_hyperbolic_distance_symmetry() {
    // Distance should be symmetric: d(a,b) == d(b,a)
    let a = Coordinates { r: 0.3, theta: 0.5 };
    let b = Coordinates { r: 0.7, theta: 2.0 };
    
    let d_ab = a.hyperbolic_distance(&b);
    let d_ba = b.hyperbolic_distance(&a);
    
    assert!((d_ab - d_ba).abs() < 1e-10, "Distance should be symmetric: d(a,b)={}, d(b,a)={}", d_ab, d_ba);
}

#[test]
fn test_normalize_theta_positive_wrap() {
    // Test that theta > 2*PI wraps around
    let mut coord = Coordinates { r: 0.5, theta: 3.0 * PI };
    coord.normalize();
    assert!(coord.theta >= 0.0 && coord.theta < 2.0 * PI, "Normalized theta should be in [0, 2*PI), got {}", coord.theta);
}

#[test]
fn test_normalize_theta_negative_wrap() {
    // Test that negative theta wraps around
    let mut coord = Coordinates { r: 0.5, theta: -PI };
    coord.normalize();
    assert!(coord.theta >= 0.0 && coord.theta < 2.0 * PI, "Normalized theta should be in [0, 2*PI), got {}", coord.theta);
}

#[test]
fn test_find_greedy_hop_empty_neighbors() {
    use crate::topology::find_greedy_hop;
    
    let target = Coordinates { r: 0.5, theta: PI };
    let neighbors: Vec<(u32, Coordinates)> = vec![];
    
    let result = find_greedy_hop(target, neighbors);
    assert!(result.is_none(), "Should return None for empty neighbor list");
}

#[test]
fn test_find_greedy_hop_single_neighbor() {
    use crate::topology::find_greedy_hop;
    
    let target = Coordinates { r: 0.5, theta: PI };
    let neighbors = vec![(1u32, Coordinates { r: 0.3, theta: PI / 2.0 })];
    
    let result = find_greedy_hop(target, neighbors);
    assert_eq!(result, Some(1u32), "Should return the only neighbor");
}

#[test]
fn test_find_greedy_hop_chooses_closest() {
    use crate::topology::find_greedy_hop;
    
    let target = Coordinates { r: 0.5, theta: 0.0 };
    let neighbors = vec![
        (1u32, Coordinates { r: 0.4, theta: 0.1 }),    // Close to target
        (2u32, Coordinates { r: 0.8, theta: PI }),     // Far from target
        (3u32, Coordinates { r: 0.6, theta: 0.05 }),   // Also close
    ];
    
    let result = find_greedy_hop(target, neighbors);
    assert!(result.is_some(), "Should find a neighbor");
    // Should pick one of the close neighbors (1 or 3)
    let chosen = result.unwrap();
    assert!(chosen == 1 || chosen == 3, "Should choose one of the close neighbors, got {}", chosen);
}

#[test]
fn test_hyperbolic_distance_negative_denominator() {
    // Construct coordinates that would cause negative denominator
    // This happens when (1 - r^2) * (1 - r'^2) becomes negative or zero
    let coord1 = Coordinates { r: 1.1, theta: 0.0 }; // Invalid: r > 1
    let coord2 = Coordinates { r: 0.5, theta: 0.0 };
    
    let dist = coord1.hyperbolic_distance(&coord2);
    assert!(dist.is_infinite(), "Should return INFINITY for invalid coordinates with negative denominator");
}
