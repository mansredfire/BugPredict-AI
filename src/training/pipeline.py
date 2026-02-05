def train_vulnerability_model(self, feature_data: Optional[pd.DataFrame] = None):
    """Train the vulnerability type classifier"""
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, accuracy_score
    from sklearn.preprocessing import LabelEncoder
    
    self.logger.info("Training vulnerability classifier...")
    
    if feature_data is None:
        feature_data = self.feature_data
    
    # Get only numeric columns
    numeric_cols = feature_data.select_dtypes(include=['int64', 'float64']).columns.tolist()
    X = feature_data[numeric_cols]
    
    # Get target from processed reports
    y = [getattr(r, 'vulnerability_type', 'Unknown') for r in self.processed_reports]
    
    # Encode target
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)
    
    # Split data (with or without stratification based on dataset size)
    try:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
        )
    except ValueError:
        # Not enough samples for stratification
        self.logger.warning("Too few samples for stratification, splitting without stratify")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_encoded, test_size=0.2, random_state=42
        )
    
    # Train model
    self.vulnerability_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        random_state=42,
        n_jobs=-1
    )
    
    self.vulnerability_model.fit(X_train, y_train)
    
    # Evaluate
    y_pred = self.vulnerability_model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    self.logger.info(f"Vulnerability classifier accuracy: {accuracy:.3f}")
    
    # Store label encoder
    self.vulnerability_label_encoder = le
    
    return self.vulnerability_model

def train_severity_model(self, feature_data: Optional[pd.DataFrame] = None):
    """Train the severity predictor"""
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, accuracy_score
    from sklearn.preprocessing import LabelEncoder
    
    self.logger.info("Training severity predictor...")
    
    if feature_data is None:
        feature_data = self.feature_data
    
    # Get only numeric columns
    numeric_cols = feature_data.select_dtypes(include=['int64', 'float64']).columns.tolist()
    X = feature_data[numeric_cols]
    
    # Get target from processed reports
    y = [getattr(r, 'severity', 'medium') for r in self.processed_reports]
    
    # Encode target
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)
    
    # Split data (with or without stratification based on dataset size)
    try:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
        )
    except ValueError:
        # Not enough samples for stratification
        self.logger.warning("Too few samples for stratification, splitting without stratify")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_encoded, test_size=0.2, random_state=42
        )
    
    # Train model
    self.severity_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        random_state=42,
        n_jobs=-1
    )
    
    self.severity_model.fit(X_train, y_train)
    
    # Evaluate
    y_pred = self.severity_model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    self.logger.info(f"Severity predictor accuracy: {accuracy:.3f}")
    
    # Store label encoder
    self.severity_label_encoder = le
    
    return self.severity_model
