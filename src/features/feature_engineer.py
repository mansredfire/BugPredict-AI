def _compute_feature_stats(self, df):
    """Compute feature statistics for normalization"""
    
    # Select only numeric columns for statistics
    numeric_cols = df.select_dtypes(include=['number']).columns.tolist()
    
    if not numeric_cols:
        print("Warning: No numeric columns found for statistics")
        self.feature_stats = {
            'mean': {},
            'std': {},
            'min': {},
            'max': {}
        }
        return
    
    # Compute statistics only on numeric columns
    numeric_df = df[numeric_cols]
    
    self.feature_stats = {
        'mean': numeric_df.mean().to_dict(),
        'std': numeric_df.std().to_dict(),
        'min': numeric_df.min().to_dict(),
        'max': numeric_df.max().to_dict()
    }
    
    print(f"Computed statistics for {len(numeric_cols)} numeric features")
